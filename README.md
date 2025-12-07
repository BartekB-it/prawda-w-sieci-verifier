# Prawda w sieci – Verifier (weryfikacja linków i kodów QR)

**DEMO online:** [https://prawda-w-sieci-verifier.onrender.com/](https://prawda-w-sieci-verifier.onrender.com/)

Prototyp mechanizmu, który w docelowej wersji ma działać jako **moduł aplikacji mObywatel** i pomaga obywatelowi sprawdzić, czy strona podająca się za serwis administracji publicznej (domena `gov.pl`) jest zaufana.

Aplikacja pozwala:

- wkleić **adres URL** i zweryfikować go,
- **zeskanować kod QR** i sprawdzić zaszyty w nim link,
- sprawdzić:
  - czy domena jest w strefie **`.gov.pl`**,
  - czy adres używa **HTTPS**,
  - czy strona przechodzi **weryfikację certyfikatu TLS/SSL po stronie serwera**,
  - czy domena jest na **białej liście oficjalnych domen** (`domains.json`),
- zbudować prosty **flow z jednorazowym tokenem (nonce)** pod integrację z aplikacją **mObywatel**.

> Wersja demo:  
> `https://prawda-w-sieci-verifier.onrender.com`  
> (adres możesz zmienić na swój, jeśli zdeployujesz projekt samodzielnie)

---

## Architektura

- **Backend:** Python + Flask + Gunicorn
- **Frontend:** czyste HTML + CSS + vanilla JS
- **Hosting (demo):** Render (Free tier)
- **Dodatkowe dane:** `domains.json` – lista zaufanych domen `gov.pl` wykorzystana w prototypie

Struktura repozytorium:

```text
.
├── backend.py        # Flask + API do walidacji URL, TLS, sesji, metadanych certyfikatu
├── domains.json      # Biała lista oficjalnych domen gov.pl (na potrzeby prototypu)
├── index.html        # Interfejs użytkownika (widok "mObywatel" + widżet weryfikacji)
├── script.js         # Logika frontendu (input URL, wywołania API, QR, render wyników)
├── style.css         # Stylizacja interfejsu (mock mObywatel / gov.pl)
└── requirements.txt  # Zależności Pythona
```

---

## Funkcje

### 1. Weryfikacja ręcznie wklejonego adresu URL

Flow:

1. Użytkownik wpisuje lub wkleja adres (np. `gov.pl`, `https://elblag.piw.gov.pl`).
2. Frontend:
   - przycina whitespace,
   - jeśli brak `http://`/`https://` → dokleja `https://`,
   - wywołuje:

     ```http
     GET /api/check-tls?url={URL}
     ```

3. Backend (`/api/check-tls`):
   - normalizuje URL (dodaje schemat, ogranicza długość),
   - dopuszcza tylko `http` / `https`,
   - **odrzuca adresy IP i sieci prywatne** (ochrona przed SSRF),
   - wymusza **domenę `gov.pl`** oraz/lub obecność na białej liście `domains.json`,
   - sprawdza TLS:

     - tylko jeśli adres używa HTTPS,
     - używa `requests.get(..., verify=True, timeout=5)`,
     - rozróżnia:
       - certyfikat OK,
       - błąd certyfikatu (SSLError),
       - brak połączenia / timeout itd.,

   - buduje metadane:

     ```json
     {
       "domain": "elblag.piw.gov.pl",
       "is_gov_pl": true,
       "uses_https": true,
       "in_trusted_list": true,
       "tls_ok": true,
       "tls_error": null,
       "http_status": 200
     }
     ```

4. Frontend wyświetla wynik:
   - domena (`gov.pl`, `pudelek.gov.pl`, itp.),
   - czy `.gov.pl`,
   - czy URL ma `https://`,
   - wynik TLS z backendu (OK / błąd / niedostępne),
   - czy domena jest na liście zaufanych (`domains.json`),
   - **podsumowanie**:
     - „Strona wygląda na zaufaną” tylko jeśli:
       - `is_gov_pl === true`
       - **`backendTls === true`**
       - `isTrusted === true`
     - w każdym innym przypadku – ostrzeżenie.

---

### 2. Skanowanie kodów QR

- Interfejs zawiera widok „Skanowanie kodu QR” i przycisk **„Zeskanuj kod QR”**.
- W trybie demo wykorzystujemy bibliotekę typu `html5-qrcode` (zależnie od integracji) do odczytu kodu QR z kamery.
- Po zeskanowaniu:
  - z kodu QR wyciągany jest URL,
  - trafia do dokładnie **tego samego flow walidacji**, co ręcznie wpisany adres:
    - normalizacja, walidacja, `check-tls`, biała lista, podsumowanie.

Dzięki temu zarówno link wklejony ręcznie, jak i link z QR przechodzą identyczną ścieżkę bezpieczeństwa.

---

### 3. Sesje jednorazowe (nonce) pod mObywatel

Backend implementuje prosty model sesji z tokenami (nonce), które mogą być zaszyte w kodzie QR:

- `POST /api/create-session`
  - wejście: `{ "url": "https://example.gov.pl" }`
  - backend:
    - waliduje URL,
    - tworzy losowy token (`secrets.token_urlsafe(...)`),
    - zapisuje sesję w pamięci: URL, `status="pending"`, timestamp, TTL,
    - zwraca:
      ```json
      {
        "ok": true,
        "token": "ABC123...",
        "qr_payload": "https://prawda-w-sieci-verifier.onrender.com/verify?token=ABC123...",
        "expires_in": 120
      }
      ```
- `POST /api/confirm-session`
  - endpoint przewidziany dla „zaufanego” klienta (np. mObywatel),
  - przyjmuje token, podejmuje decyzję (confirmed / rejected) i zwraca wynik.
- `GET /api/session-status`
  - pozwala widgetowi na stronie odpytywać status:
    - `pending / confirmed / rejected / expired`,
    - plus powód / opis.

To dokładnie realizuje koncepcję: jednorazowy kod QR → aplikacja mObywatel → widoczny wynik w aplikacji i na stronie.

---

### 4. Metadane certyfikatu TLS (opcjonalne API)

Dodatkowe API:

```http
GET /api/cert-metadata?url={URL}
```

- akceptuje tylko `https://`,
- wykonuje handshake TLS przy użyciu `ssl` + `socket`,
- pobiera certyfikat serwera (`getpeercert()`),
- zwraca uproszczone metadane, m.in.:
  - `subject`
  - `issuer`
  - `not_before` / `not_after` (daty ważności)
  - `subject_alt_names` (DNS z SAN)
  - `serialNumber`, `version`

To jest programowa odpowiedź na wymaganie typu:

> „sprawdź certyfikat dowolnym toolem, np. `openssl s_client -showcerts ...`”

---

## Bezpieczeństwo

W prototypie zaimplementowano kilka istotnych zabezpieczeń:

- **Walidacja wejścia po stronie backendu:**
  - tylko `http://` i `https://`,
  - limit długości URL,
  - zakaz adresów IP i prywatnych podsieci (ochrona przed SSRF),
  - domena musi być w strefie `gov.pl` i/lub na whiteliście `domains.json`.

- **Ścisła definicja zaufania:**
  - „zaufana” strona = `.gov.pl` + `TLS_OK` (backend) + obecność w `domains.json`.

- **TLS/SSL:**
  - backend realnie weryfikuje certyfikat (`verify=True`),
  - rozróżnia błąd certyfikatu od błędu sieci.

- **XSS / błędy:**
  - backend nie zwraca surowych wyjątków (brak `str(e)` wprost do użytkownika),
  - frontend escapuje komunikaty (`escapeHtml(...)`),
  - nawet przy dziwnych inputach (np. próby wstrzyknięcia `<script>`) UI pokazuje tylko bezpieczny tekst.

- **Ograniczenie danych:**
  - brak logowania danych osobowych,
  - sesje QR są krótkotrwałe, trzymane w pamięci, bez identyfikacji użytkownika.

---

## Uruchomienie lokalne

1. Sklonuj repozytorium:

   ```bash
   git clone https://github.com/TWOJ-USER/prawda-w-sieci-verifier.git
   cd prawda-w-sieci-verifier
   ```

2. Zainstaluj zależności:

   ```bash
   pip install -r requirements.txt
   ```

3. Uruchom backend w trybie deweloperskim:

   ```bash
   python backend.py
   ```

4. Wejdź w przeglądarce na:

   ```text
   http://127.0.0.1:5000/
   ```

---

## Licencja

Prototyp na potrzeby wyzwania „Prawda w sieci”.  
Możesz dodać np. licencję MIT lub Apache-2.0 według własnych potrzeb.
