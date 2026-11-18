# Skaner linii papilarnych

Ekstrakcja minutiae z obrazów odcisków, dopasowanie 1:1 oraz bezpieczny protokół
klient–serwer (X25519 + AES-256-GCM, mTLS, tokeny JWT, ochrona przed replay,
szyfrowanie szablonów w bazie). Opis projektu: `docs/Skaner_Linii_Papilarnych.docx`.

## Struktura

```text
src/fpscanner/
├── biometrics/   preprocessing.py (obraz -> minutiae, .tpl), matching.py (dopasowanie 1:1)
├── security/     crypto_session, replay_guard, template_vault, vault_transit,
│                 tls_config, device_auth, session_tokens, totp
├── server/       api_service (logika endpointów), http_app (adapter FastAPI), wire_protocol,
│                 template_repository (InMemory/PostgreSQL), server_config (budowa serwisu z FP_* ze środowiska)
├── client/       api_client.py (FingerprintClient, HttpsTransport)
└── tools/        evaluate_fvc (EER/FMR/FNMR), provision_dev (środowisko deweloperskie),
                  nginx_conf (generator konfiguracji reverse proxy),
                  smoke_test (test dymny wdrożenia), bench_verify (benchmark weryfikacji)
deploy/           nginx.conf (fragment do /etc/nginx/conf.d/, generowany)
docker/           entrypoint.sh (wczytuje FP_* z pliku, nie wykonuje go)
tests/            testy pytest: jednostkowe, własności (Hypothesis), integracyjne z nginx
                  (test_proxy_integration, pomijany bez nginx)
Dockerfile, docker-compose.yml, .github/workflows/ci.yml
data/             bazy FVC (poza gitem)
docs/             dokumentacja projektu
```

Kierunek zależności: `biometrics` i `security` nie importują niczego z `server`/`client`;
`server` i `client` korzystają z `security` i `biometrics`.

## Instalacja

```bash
python -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\Activate.ps1
pip install -e ".[dev]"
pytest -q
```

## Użycie

```bash
# ekstrakcja minutiae (pojedynczy plik lub katalog)
fp-extract data/FVC2002/Db1_b/101_1.tif --debug --out output

# ocena jakości na bazie FVC (nazwy plików: <palec>_<odbitka>.tif)
fp-evaluate data/FVC2002/Db1_b --jobs 4 --out eval_output
fp-evaluate data/FVC2002/Db1_b --sweep dist_tol 8 10 12 15

# środowisko deweloperskie (PKI, klucze, rejestr urządzeń) -> katalog dev/
# --local-kek: KEK-i w zmiennych zamiast Vaulta (tylko lokalne próby bez Dockera)
fp-provision-dev --out dev --readers reader-01 --admins admin-01 --local-kek
```

Odpowiedniki bez instalacji poleceń: `python -m fpscanner.tools.evaluate_fvc ...`,
`python -m fpscanner.biometrics.preprocessing ...`, `python -m fpscanner.tools.provision_dev ...`.

## Uwierzytelnienie urządzenia: mTLS, dowód HMAC i TOTP

Handshake urządzenia łączy trzy niezależne czynniki (`DevicePolicy`, domyślnie wszystkie włączone):

| Czynnik | Co dowodzi | Czym jest chroniony przed powtórzeniem |
| --- | --- | --- |
| mTLS | urządzenie ma klucz prywatny certyfikatu z rejestru | handshake TLS 1.3 |
| dowód HMAC-SHA256 | zna sekret urządzenia; wiąże `device_id`, klucz efemeryczny, losowość i `ts` | nonce (`client_random`) zajmowany jednorazowo w `ReplayGuard`, okno czasowe 60 s |
| **TOTP (RFC 6238)** | zna *osobny* sekret TOTP i ma zegar zsynchronizowany z serwerem | jednorazowość kroku (`TotpReplayTracker`) |

**Jak działa TOTP** (`security/totp.py`, zależy tylko od biblioteki standardowej):

- HOTP wg RFC 4226 z licznikiem `T = floor(czas / 30 s)`; domyślnie HMAC-SHA256 i 6 cyfr. Implementację
  sprawdzają wektory z RFC 4226 (dod. D) i RFC 6238 (dod. B, SHA-1/256/512) w `tests/test_totp.py`.
- Klient wysyła kod w polu `totp` handshake'u. Sekret TOTP jest **inny** niż sekret dowodu (rejestr odrzuca
  identyczne), więc wyciek jednego nie daje drugiego czynnika. Każde urządzenie ma go w `devices.json`
  (`totp_secret`), a `fp-provision-dev` generuje go i zapisuje też w pliku klienta.
- **Synchronizacja czasu.** Serwer liczy kod z *własnego* zegara (nie ze znacznika `ts` podanego przez
  klienta) i akceptuje kroki `c-1 … c+1`. Zegar urządzenia spóźniony o więcej niż 30-60 s (zależnie od
  położenia w kroku) jest odrzucany, nawet gdy `ts` mieści się w oknie 60 s. Zegar spieszący się
  ogranicza i tak znacznik czasu (tolerancja 5 s).
- **Jednorazowość** (RFC 6238, §5.2): dla każdego urządzenia serwer pamięta ostatnio przyjęty krok i
  odrzuca kod z kroku nie nowszego (`409 replay_detected`). Kod jest zużywany dopiero po
  uwierzytelnieniu pozostałych czynników i zajęciu nonce'a, więc nieudane próby nie spalają kroku
  prawowitego urządzenia. Powtórzony, przechwycony handshake dostaje `409` już na nonce'ie.
- Czynnik przedstawiony jest zawsze weryfikowany, także gdy polityka go nie wymaga (jak certyfikat i dowód).

Włączanie: `FP_REQUIRE_TOTP=1` (domyślnie). Serwer nie wystartuje, jeśli któreś urządzenie w
`FP_DEVICES_FILE` nie ma `totp_secret`. Klient: `FingerprintClient(..., totp_secret=...)`.

## Uruchomienie za reverse proxy (TLS 1.3 + mTLS)

```text
klient --TLS 1.3 + mTLS--> nginx --HTTP, 127.0.0.1--> uvicorn (http_app)
```

```bash
fp-provision-dev --out dev --readers reader-01 --admins admin-01 --behind-proxy --local-kek
# 1. aplikacja (zmienne z dev/server.env; Windows: ustaw je ręcznie)
set -a; . dev/server.env; set +a; fp-server              # 127.0.0.1:8000
# 2. nginx bez roota, konfiguracja wygenerowana w dev/nginx.conf
nginx -c "$PWD/dev/nginx.conf" -p "$PWD/dev/run"           # 127.0.0.1:8443
# 3. klient: HttpsTransport("https://127.0.0.1:8443", tls_config.client_ssl_context(...))
```

Zasady, na których opiera się bezpieczeństwo tego układu:

- aplikacja słucha tylko na loopbacku (`FP_HOST`, domyślnie 127.0.0.1) i ufa nagłówkom
  `X-Forwarded-For`/`X-Client-Cert` wyłącznie od adresów z `FP_TRUSTED_PROXIES`;
- nginx **nadpisuje** te nagłówki, więc wartości od klienta nie docierają do aplikacji;
- uvicorn musi działać z `--no-proxy-headers` (`fp-server` robi to sam). Domyślnie
  podmienia adres połączenia na adres z `X-Forwarded-For` i aplikacja odrzuci wtedy
  każdego klienta (zweryfikowane testem);
- nginx nie ma SHA-256 certyfikatu klienta (jego `$ssl_client_fingerprint` to SHA-1),
  dlatego przekazuje cały certyfikat (`$ssl_client_escaped_cert`), a SHA-256 liczy aplikacja;
- produkcja: `deploy/nginx.conf` do `/etc/nginx/conf.d/fp.conf`, certyfikat serwera i CA
  klientów z własnego PKI (nie z `provision_dev`).

Zmienne środowiskowe adaptera: `FP_HOST`, `FP_PORT`, `FP_LOG_LEVEL`; reszta jak w
`server_config` (m.in. `FP_TRUSTED_PROXIES`, `FP_CERT_HEADER`, `FP_CERT_VERIFY_HEADER`).

## Docker Compose

```bash
cp .env.example .env                           # opcjonalnie: zmień porty/hasła deweloperskie
docker compose up -d --build                   # provision -> postgres/vault -> api -> proxy (nginx, mTLS)
docker compose --profile test run --rm smoke   # test dymny przez nginx
docker compose down -v                         # kasuje też wolumeny (klucze, baza)
```

Jeden stos: nginx (TLS 1.3 + mTLS) -> API (FastAPI) -> PostgreSQL 16, a klucz główny (KEK) siedzi w
Vault Transit. Wszystko w wersji deweloperskiej.

- `provision` raz generuje PKI, klucze i rejestr urządzeń do wolumenu `fp-data` (gdy
  `/data/server.env` już istnieje, nic nie robi, więc klucze przeżywają restart).
- `vault-init` włącza silnik Transit i tworzy klucz `fp-kek`. Vault działa w trybie `-dev` (pamięć), więc
  po jego restarcie KEK znika razem z możliwością odczytu rekordów: zacznij od `down -v`.
- `api` nie wystawia portów; jedyny zaufany adres proxy to `172.28.0.10` (stały adres nginx w
  sieci `fpnet`). Kontener działa jako użytkownik nieuprzywilejowany, z `read_only`, `cap_drop: ALL`.
- Klucze klienta do prób z hosta: `docker compose cp provision:/data/clients ./dev-clients`
  (zawierają sekrety, nie commituj). nginx nasłuchuje na `127.0.0.1:8443`.

## Trwałość i klucze (PostgreSQL, Vault)

| Zmienna | Znaczenie |
| --- | --- |
| `FP_DATABASE_URL` | DSN PostgreSQL. Bez niego szablony są w pamięci procesu (tylko testy). Produkcja: `sslmode=verify-full` |
| `FP_KEY_PROVIDER` | `vault` (domyślnie) albo `local` (KEK-i w zmiennych `FP_KEK_*`, wyłącznie testy i benchmarki) |
| `FP_VAULT_ADDR`, `FP_VAULT_TOKEN` / `FP_VAULT_TOKEN_FILE`, `FP_VAULT_KEY`, `FP_VAULT_MOUNT`, `FP_VAULT_NAMESPACE`, `FP_VAULT_CACERT` | Vault Transit; `http://` tylko z `FP_VAULT_ALLOW_HTTP=1` |
| `FP_JWT_KEY` | klucz HMAC tokenów JWT (base64url, >= 32 B) |
| `FP_MAX_FAILURES_DEVICE`, `FP_LOCKOUT_WINDOW_S` | limit nieudanych weryfikacji na urządzenie (domyślnie 50 w 300 s) |

Adapter PostgreSQL: `pip install -e ".[postgres]"` (obraz Dockera go zawiera).

**Vault Transit.** Klucz musi mieć `derived=true` (AAD trafia do Transit jako `context`; dla kluczy zwykłych
Vault ignorowałby go po cichu, więc adapter odmawia startu):

```bash
vault write transit/keys/fp-kek type=aes256-gcm96 derived=true
```

Minimalna polityka aplikacji: `update` na `transit/encrypt/fp-kek` i `transit/decrypt/fp-kek`, `read` na
`transit/keys/fp-kek`. Na produkcji token z AppRole przez Vault Agent (`FP_VAULT_TOKEN_FILE`), nie token roota.
Identyfikator KEK-a w rekordzie to `fp-kek:v<wersja>`. Awaria Vaulta/bazy daje `503 unavailable`
(nie `500` i nie zalicza się do prób weryfikacji).

**Rotacja KEK-a** robi sam Vault:

```bash
vault write -f transit/keys/fp-kek/rotate
```

Nowe rekordy dostają `fp-kek:v2`, a stare (`fp-kek:v1`) dalej się odszyfrowują, bo Transit trzyma
poprzednie wersje klucza (test: `test_vault_rotation_keeps_old_records_readable`). Rekordów nie przepakowujemy
masowo; `rewrap` z `template_vault` zostaje jako funkcja biblioteczna. Wersję można wycofać przez
`min_decryption_version`, ale dopiero gdy żaden rekord (ani kopia zapasowa) jej nie używa.

## Ograniczenia

- **Jeden proces.** Nonce'y (`InMemoryNonceStore`), sesje (`SessionStore`) i limit prób
  (`AttemptLimiter`) są w pamięci procesu. Przy wielu procesach kieruj każde urządzenie zawsze do tego
  samego (np. `hash $ssl_client_fingerprint consistent` w nginx) albo wymień magazyn nonce'ów na wspólny
  (interfejs `NonceStore`). Restart serwera czyści nonce'y i kończy wszystkie sesje. Przez pierwsze 60 s
  (okno czasowe) można wtedy powtórzyć przechwycony handshake, ale sesji to nie przejmuje, bo klucz
  efemeryczny zna tylko klient.
- **Limit prób tylko per urządzenie.** Nie ma blokady per osoba (byłaby DoS-em na konkretną osobę) ani
  limitu handshake'ów per IP (to robi nginx: `limit_req` i mTLS). Atakujący z zarejestrowanym czytnikiem
  ma więc do 50 prób na 5 minut, wspólnych dla wszystkich osób.
- **Jeden handshake na krok TOTP (30 s) na urządzenie.** To skutek jednorazowości kodu. Klient
  (`FingerprintClient.connect`) sam czeka do następnego kroku, gdy ten już zużył, więc w praktyce
  ponowne połączenie tuż po poprzednim trwa do 30 s dłużej. Dotyczy to też benchmarku, który wyłącza TOTP.
  Stan `TotpReplayTracker` jest w pamięci procesu, jak nonce'y i sesje.
- **Jeden klucz JWT.** Jego wymiana to restart serwera (tokeny żyją 15 minut).
- **KEK lokalny** (`FP_KEY_PROVIDER=local`) służy tylko do testów i benchmarków.

## CI i jakość

```bash
ruff check .                                   # lint (konfiguracja w pyproject.toml)
pytest -q                                      # wszystkie testy
HYPOTHESIS_PROFILE=ci pytest -q tests/test_properties.py   # testy własności, 300 przykładów
python -m fpscanner.tools.bench_verify --threads 1 2 4 8   # przepustowość weryfikacji
```

GitHub Actions (`.github/workflows/ci.yml`): lint, testy (z nginx) i zbudowanie stosu compose z
testem dymnym.

## Git

```bash
git init -b main
git add -A && git status --short               # sprawdź: bez dev/, *.key, *.env, data/*
git commit -m "Pierwszy commit"
```

## Serwis z wygenerowanego środowiska

```python
from fpscanner.server.server_config import build_service
svc, trust = build_service(env_dict)   # albo bez argumentu: z os.environ (FP_*)
```

`dev/` zawiera klucze prywatne i sekrety, jest w `.gitignore`. Na produkcji KEK ma
być w HSM/Vault, a CA poza maszyną aplikacji.
