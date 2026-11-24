# Bezpieczny Skaner Linii Papilarnych z Kryptograficznym Zabezpieczeniem Danych Biometrycznych

## Cel i zakres projektu

Celem projektu jest zaprojektowanie i implementacja systemu skanera linii papilarnych, w którym dane biometryczne są chronione na każdym etapie przetwarzania. Szczególny nacisk położony zostaje na odporność systemu na ataki typu replay attack.

## Architektura systemu

| Warstwa | Opis |
| --- | --- |
| Akwizycja | Czytnik linii papilarnych (USB/SPI) lub symulator obrazu na potrzeby testow. Obraz 8-bit grayscale, rozdzielczosc >=500 DPI. |
| Preprocessing | Normalizacja obrazu, segmentacja, ekstrakcja minutiae (algorytm Crossing Number). Wynik: wektor cech. |
| Kryptografia | Szyfrowanie szablonu kluczem sesyjnym AES-256-GCM. Generowanie nonce (96-bit, CSPRNG) dla kazdej sesji. |
| Transmisja | REST API (HTTPS / TLS 1.3). Kazdy request zawiera: token sesji, timestamp, nonce, zaszyfrowany szablon + tag GCM. |
| Serwer | Weryfikacja tokenu i nonce (baza uzytych nonce'ow + okno czasowe). Dopasowanie za pomoca algorytmu minutiae matching. Szablony w bazie zaszyfrowane AES-256, klucze w HSM/vault. |

## Ochrona przed atakami Replay Attack

Mechanizmy zastosowane w projekcie:

1. **Nonce jednorazowy** – każdy request klienta zawiera kryptograficznie losowy nonce (96 bitow, CSPRNG). Serwer przechowuje listę użytych nonce'ow w konkretnym oknie czasowym (np. 5 minut). Ponowne użycie nonce'a skutkuje odrzuceniem żądania.

2. **Timestamp + okno czasowe** – każdy pakiet zawiera znacznik czasu UTC. Serwer odrzuca pakiety starsze niż delta T (konfigurowalne, domyślnie 60 s), co eliminuje późne odtworzenie przechwyconego komunikatu.

3. **Token sesji (JWT / HMAC)** – po uwierzytelnieniu wydawany jest krótko życiowy token sesji (np. 15 min). Token będzie powiązany z identyfikatorem urządzenia i adresem IP, co utrudnia jego przechwycenie i użycie.

4. **Mutual TLS (mTLS)** – opcjonalnie: obustronny TLS zapewnia, ze tylko zarejestrowane urządzenia mogą się połączyć z serwerem, co blokuje Man-in-the-Middle.

## Stos technologiczny

| Obszar | Technologia / biblioteka | Zastosowanie |
| --- | --- | --- |
| Język backend | Python 3.12 | Logika serwera, przetwarzanie obrazu |
| Język klient | Python 3.12 / C (embedded) | Sterownik czytnika, klient API |
| Przetwarzanie obrazu | OpenCV 4.x, NumPy | Preprocessing, ekstrakcja minutiae |
| Kryptografia | PyCA | AES-256-GCM, HMAC-SHA256, HKDF |
| Komunikacja | FastAPI + Uvicorn, HTTPS/TLS 1.3 | REST API, walidacja tokenow |
| Baza danych | PostgreSQL 16 + pgcrypto | Szyfrowanie szablonow w bazie |
| Zarzadzanie kluczami | HashiCorp Vault | Przechowywanie kluczy AES, rotacja |
| Autentykacja | PyJWT, python-jose | Generowanie i weryfikacja JWT |
| Testy | pytest | Testy jednostkowe i property-based |
| CI/CD | GitHub Actions | Automatyczne testy i linting |
| Konteneryzacja | Docker, docker-compose | Środowisko deweloperskie i testowe |

## Możliwe ryzyka i ograniczenia

- **Dostępność sprzętu** – projekt można realizować na symulowanych obrazach odcisków (bazy FVC2002/FVC2004) bez fizycznego czytnika.

- **FAR / FRR** – zmienność odcisków może wpływać na wskaźniki błędu; konieczne strojenie progu dopasowania.

- **Zarzadzanie kluczami** – utrata klucza głównego to brak dostępu do bazy. Wymagana polityka backup + rotacji.

- **RODO / GDPR** – dane biometryczne są danymi szczególnymi. Implementacja musi respektować zasadę minimalizacji danych i prawa do usunięcia.
