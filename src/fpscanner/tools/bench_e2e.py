#!/usr/bin/env python3
"""Benchmark end-to-end przez HTTPS/mTLS i nginx dla działającego wdrożenia.

Każdy plik --clients musi opisywać INNE urządzenie (inne device_id, certyfikat,
sekret i TOTP). Jeden poprawny handshake na urządzenie jest wykonywany przed
obciążeniem; sesje są następnie używane do pomiarów verify. Dzięki temu nie
przekraczamy limitu jednego użycia kodu TOTP w danym kroku 30 s.

Przykład wewnątrz sieci Docker Compose:
  python -m fpscanner.tools.bench_e2e --url https://proxy:8443 \\
      --clients /data/clients/reader-01.json /data/clients/admin-01.json \\
      --threads 1 2 --seconds 10 --warmup 5

Pliki wynikowe: CSV z pojedynczymi próbkami oraz CSV z podsumowaniem.
"""
from __future__ import annotations

import argparse
import csv
import json
import statistics
import sys
import threading
import time
import uuid
from pathlib import Path

from fpscanner.client.api_client import ApiClientError
from fpscanner.tools.smoke_test import make_client, synthetic_template


def percentile(values: list[float], q: float) -> float:
    """Percentyl nearest-rank; q w zakresie 0..1."""
    ordered = sorted(values)
    if not ordered:
        raise ValueError("brak próbek")
    return ordered[max(0, min(len(ordered) - 1, int(q * len(ordered) + 0.999999) - 1))]


def summarize(operation: str, workers: int, latencies: list[float],
              elapsed: float, errors: int) -> dict:
    if not latencies:
        return {"operation": operation, "workers": workers, "samples": 0,
                "errors": errors, "throughput_ops_s": 0.0,
                "p50_ms": "", "p95_ms": "", "p99_ms": "",
                "elapsed_s": round(elapsed, 4)}
    return {"operation": operation, "workers": workers, "samples": len(latencies),
            "errors": errors,
            "throughput_ops_s": round(len(latencies) / elapsed, 3) if elapsed else 0.0,
            "p50_ms": round(statistics.median(latencies) * 1000, 3),
            "p95_ms": round(percentile(latencies, .95) * 1000, 3),
            "p99_ms": round(percentile(latencies, .99) * 1000, 3),
            "elapsed_s": round(elapsed, 4)}


def write_csv(path: Path, rows: list[dict]) -> None:
    if rows:
        with path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=list(rows[0]))
            writer.writeheader()
            writer.writerows(rows)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--url", required=True, help="adres nginx, np. https://proxy:8443")
    ap.add_argument("--clients", nargs="+", required=True, type=Path,
                    help="pliki clients/<device>.json; każdy musi opisywać inne urządzenie")
    ap.add_argument("--threads", nargs="+", type=int, default=[1, 2],
                    help="liczba równoległych klientów; maksymalnie tyle, ile plików --clients")
    ap.add_argument("--seconds", type=float, default=10.0, help="czas pomiaru dla każdego poziomu obciążenia")
    ap.add_argument("--warmup", type=int, default=5, help="niewliczane verify na klienta przed pomiarem")
    ap.add_argument("--subjects", type=int, default=20, help="liczba syntetycznych wzorców")
    ap.add_argument("--minutiae", type=int, default=50)
    ap.add_argument("--out", type=Path, default=Path("."), help="katalog wyników CSV")
    a = ap.parse_args()

    if a.seconds <= 0 or a.warmup < 0 or a.subjects < 1 or a.minutiae < 1:
        ap.error("--seconds musi być > 0, --warmup >= 0, --subjects i --minutiae >= 1")
    if not a.threads or any(n < 1 for n in a.threads):
        ap.error("--threads musi zawierać dodatnie liczby")
    if max(a.threads) > len(a.clients):
        ap.error(f"test {max(a.threads)}-wątkowy wymaga {max(a.threads)} różnych urządzeń; "
                 f"podano {len(a.clients)} pliki. Nie współdziel device_id między wątkami "
                 "ze względu na jednorazowy TOTP.")
    if len({p.resolve() for p in a.clients}) != len(a.clients):
        ap.error("ten sam plik klienta podano więcej niż raz")
    device_ids = []
    for path in a.clients:
        if not path.is_file():
            ap.error(f"nie znaleziono pliku klienta: {path}")
        try:
            device_ids.append(json.loads(path.read_text(encoding="utf-8"))["device_id"])
        except (OSError, ValueError, KeyError, TypeError):
            ap.error(f"niepoprawny plik klienta lub brak device_id: {path}")
    if len(set(device_ids)) != len(device_ids):
        ap.error("pliki --clients muszą zawierać różne device_id (unikalne urządzenia/TOTP)")

    a.out.mkdir(parents=True, exist_ok=True)
    clients = []
    sample_rows: list[dict] = []
    summary_rows: list[dict] = []
    try:
        # Handshake jest wykonywany raz dla każdego unikalnego urządzenia.
        handshake_latencies = []
        for client_file in a.clients:
            client = make_client(a.url, client_file)
            started = time.perf_counter()
            client.connect()
            elapsed = time.perf_counter() - started
            clients.append(client)
            handshake_latencies.append(elapsed)
            sample_rows.append({"operation": "handshake", "workers": 1,
                                "device": client_file.stem, "sample": 1,
                                "latency_ms": round(elapsed * 1000, 3),
                                "status": "ok", "error": ""})

        # Dane unikalne dla tego uruchomienia, aby nie kolidowały z wcześniejszymi próbami.
        run_id = uuid.uuid4().hex[:10]
        subjects = [f"bench-{run_id}-{i}" for i in range(a.subjects)]
        seed = int(run_id[:6], 16)
        templates = [synthetic_template(seed + i, a.minutiae) for i in range(a.subjects)]
        for subject, template in zip(subjects, templates, strict=True):
            clients[0].enroll(subject, template)

        summary_rows.append(summarize("handshake", len(handshake_latencies),
                                      handshake_latencies, sum(handshake_latencies), 0))
        print(f"URL: {a.url}")
        print(f"Urządzenia: {len(clients)} | osoby: {a.subjects} | minutiae: {a.minutiae}")
        print("Handshake: nowe połączenie HTTPS/TLS + mTLS + protokół handshake.")
        print("Verify: pełna ścieżka HTTPS przez endpoint nginx.\n")
        print(f"{'operacja':<12} {'wątki':>6} {'ops/s':>10} {'p50 ms':>10} "
              f"{'p95 ms':>10} {'p99 ms':>10} {'błędy':>8}")
        hs = summary_rows[-1]
        print(f"{'handshake':<12} {hs['workers']:>6} {'-':>10} "
              f"{hs['p50_ms']:>10} {hs['p95_ms']:>10} {hs['p99_ms']:>10} {0:>8}")

        for worker_count in a.threads:
            active = clients[:worker_count]
            # Rozgrzewka nie trafia do statystyk.
            for idx, client in enumerate(active):
                for j in range(a.warmup):
                    k = (idx * a.warmup + j) % len(subjects)
                    client.verify(subjects[k], templates[k])

            deadline = time.perf_counter() + a.seconds
            results: list[list[float]] = [[] for _ in active]
            errors: list[list[str]] = [[] for _ in active]

            def worker(
                index: int,
                _active=active,
                _deadline=deadline,
                _results=results,
                _errors=errors,
                _worker_count=worker_count,
            ) -> None:
                client = _active[index]
                local_i = index
                while time.perf_counter() < _deadline:
                    k = local_i % len(subjects)
                    started = time.perf_counter()
                    try:
                        matched = client.verify(subjects[k], templates[k])
                        duration = time.perf_counter() - started
                        _results[index].append(duration)
                        sample_rows.append({"operation": "verify", "workers": _worker_count,
                                            "device": a.clients[index].stem,
                                            "sample": len(_results[index]),
                                            "latency_ms": round(duration * 1000, 3),
                                            "status": "match" if matched else "no_match", "error": ""})
                    except Exception as exc:
                        duration = time.perf_counter() - started
                        message = f"{type(exc).__name__}: {exc}"
                        _errors[index].append(message)
                        sample_rows.append({"operation": "verify", "workers": _worker_count,
                                            "device": a.clients[index].stem,
                                            "sample": len(_results[index]) + len(_errors[index]),
                                            "latency_ms": round(duration * 1000, 3),
                                            "status": "error", "error": message})
                        if isinstance(exc, ApiClientError):
                            break
                    local_i += 1

            start = time.perf_counter()
            threads = [threading.Thread(target=worker, args=(i,), daemon=True)
                       for i in range(worker_count)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
            elapsed = time.perf_counter() - start
            latencies = [v for per_worker in results for v in per_worker]
            error_count = sum(len(per_worker) for per_worker in errors)
            row = summarize("verify", worker_count, latencies, elapsed, error_count)
            summary_rows.append(row)
            print(f"{'verify':<12} {worker_count:>6} {row['throughput_ops_s']:>10.1f} "
                  f"{str(row['p50_ms']):>10} {str(row['p95_ms']):>10} "
                  f"{str(row['p99_ms']):>10} {error_count:>8}")

        stamp = time.strftime("%Y%m%d_%H%M%S")
        samples_path = a.out / f"bench_e2e_{stamp}.csv"
        summary_path = a.out / f"bench_e2e_{stamp}_summary.csv"
        write_csv(samples_path, sample_rows)
        write_csv(summary_path, summary_rows)
        print(f"\nPróbki:  {samples_path}\nPodsum.: {summary_path}")
        if any(row["errors"] for row in summary_rows):
            raise SystemExit(2)
    except (ApiClientError, OSError, ValueError, KeyError) as exc:
        print(f"BŁĄD benchmarku: {type(exc).__name__}: {exc}", file=sys.stderr)
        raise SystemExit(1) from None
    finally:
        for client in clients:
            try:
                client.close()
            except Exception:
                pass


if __name__ == "__main__":
    main()
