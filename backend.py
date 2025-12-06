# backend.py
from flask import Flask, request, jsonify
import requests
from urllib.parse import urlparse
import ipaddress
import json
from pathlib import Path

# Serwujemy pliki statyczne (index.html, script.js, style.css, domains.json)
app = Flask(__name__, static_folder='.', static_url_path='')

# ---- KONFIGURACJA / DANE ----

# Maksymalna długość URL, żeby nie przyjmować absurdalnie długich stringów
MAX_URL_LENGTH = 2048

# Wczytujemy listę zaufanych domen gov.pl z domains.json
DOMAINS_PATH = Path(__file__).with_name("domains.json")

try:
    with DOMAINS_PATH.open(encoding="utf-8") as f:
        TRUSTED_DOMAINS = {
            d.strip().lower()
            for d in json.load(f)
            if isinstance(d, str) and d.strip()
        }
    print(f"[INFO] Wczytano {len(TRUSTED_DOMAINS)} zaufanych domen z domains.json")
except Exception as e:
    # W prototypie wystarczy ostrzeżenie w logach
    print(f"[WARN] Nie udało się wczytać domains.json: {e}")
    TRUSTED_DOMAINS = set()


# ---- WALIDACJA I NORMALIZACJA URL ----

def normalize_and_validate_url(raw: str) -> str:
    """
    Normalizuje URL (dodaje https:// jeśli brak) i sprawdza:
    - niepusty, niezbyt długi
    - dozwolony schemat (http/https)
    - poprawny host
    - host nie jest prywatnym / lokalnym IP (SSRF)
    - host jest w domenach .gov.pl i/lub na białej liście z domains.json
    """
    raw = (raw or "").strip()
    if not raw:
        raise ValueError("Pusty adres URL")

    if len(raw) > MAX_URL_LENGTH:
        raise ValueError("Adres URL jest zbyt długi")

    # Jeśli użytkownik podał np. 'elblag.piw.gov.pl' – dokładamy https://
    if not raw.startswith(("http://", "https://")):
        raw = "https://" + raw

    parsed = urlparse(raw)

    if parsed.scheme not in ("http", "https"):
        raise ValueError("Dozwolone są tylko protokoły http/https")

    host = parsed.hostname
    if not host:
        raise ValueError("Nie udało się odczytać domeny z adresu")

    host_l = host.lower()

    # 1) Ochrona przed SSRF na IP (localhost, sieci prywatne itd.)
    ip_obj = None
    try:
        ip_obj = ipaddress.ip_address(host_l)
    except ValueError:
        # host nie jest IP, tylko domeną – przechodzimy dalej
        ip_obj = None

    if ip_obj is not None:
        # Jeśli ktoś poda np. 127.0.0.1, 10.x.x.x, 192.168.x.x, itp. – blokujemy
        if (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_reserved
            or ip_obj.is_multicast
        ):
            raise ValueError("Adres IP jest niedozwolony")

    else:
        # 2) Domena – wymagamy gov.pl i/lub obecności na liście
        no_www = host_l[4:] if host_l.startswith("www.") else host_l

        # jeśli mamy wczytaną listę – używamy jej jako whitelisty
        if TRUSTED_DOMAINS:
            if host_l not in TRUSTED_DOMAINS and no_www not in TRUSTED_DOMAINS:
                raise ValueError("Domena nie znajduje się na liście zaufanych gov.pl")
        else:
            # fallback: tylko *.gov.pl
            if not (host_l == "gov.pl" or host_l.endswith(".gov.pl")):
                raise ValueError("Dozwolone są tylko domeny w strefie gov.pl")

    # Zwracamy znormalizowany URL
    return parsed.geturl()


# ---- ENDPOINT API DO SPRAWDZANIA TLS ----

@app.get("/api/check-tls")
def check_tls():
    raw = request.args.get("url", "")

    # 1) Walidacja wejścia + ograniczenie ekspozycji danych (czytelne, ale bez technicznych szczegółów)
    try:
        url = normalize_and_validate_url(raw)
    except ValueError as e:
        # Zwracamy tylko "bezpieczny" komunikat – bez stack trace, bez technicznego str(error) z wnętrza requests
        return jsonify({"ok": False, "error": str(e)}), 400

    # 2) Sprawdzanie TLS – z bezpiecznym traktowaniem błędów
    try:
        # verify=True (domyślnie) → sprawdza certyfikat wg zaufanych CA systemowych
        r = requests.get(url, timeout=5)
        return jsonify({
            "ok": True,
            "url": url,
            "https": url.startswith("https://"),
            "http_status": r.status_code,
            "tls_ok": True,   # handshake i certyfikat przeszły
        })
    except requests.exceptions.SSLError:
        # Nie pokazujemy szczegółów błędu SSL (ograniczenie ekspozycji)
        return jsonify({
            "ok": True,
            "url": url,
            "https": True,
            "tls_ok": False,
            "error": "Błąd weryfikacji SSL/TLS",
        })
    except requests.exceptions.RequestException:
        # Nie wyciągamy str(e) na zewnątrz – tylko ogólny komunikat
        return jsonify({
            "ok": False,
            "url": url,
            "error": "Nie udało się nawiązać połączenia z serwerem",
        }), 502


# ---- FRONT (statyczna strona) ----

@app.route("/")
def index():
    return app.send_static_file("index.html")


if __name__ == "__main__":
    app.run(debug=True)
