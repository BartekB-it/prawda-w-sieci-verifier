# backend.py
from flask import Flask, request, jsonify
import requests
from urllib.parse import urlparse
import ipaddress
import json
from pathlib import Path
import secrets
import time

# Serwujemy pliki statyczne (index.html, script.js, style.css, domains.json itp.)
app = Flask(__name__, static_folder=".", static_url_path="")

# ---- KONFIGURACJA ----

MAX_URL_LENGTH = 2048          # żeby nikt nie walił absurdalnie długich URL-i
SESSION_TTL_SECONDS = 120      # sesja QR ważna np. 120 sekund

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
    print(f"[WARN] Nie udało się wczytać domains.json: {e}")
    TRUSTED_DOMAINS = set()

# Pamięć na sesje weryfikacji QR: token -> dict z danymi sesji
SESSIONS = {}  # type: dict[str, dict]


# ---- NARZĘDZIA POMOCNICZE ----

def _is_private_ip(host: str) -> bool:
    """Sprawdza, czy host jest adresem IP z zakresów prywatnych / lokalnych."""
    try:
        ip_obj = ipaddress.ip_address(host)
    except ValueError:
        return False

    return (
        ip_obj.is_private
        or ip_obj.is_loopback
        or ip_obj.is_link_local
        or ip_obj.is_reserved
        or ip_obj.is_multicast
    )


def normalize_and_validate_url(raw: str) -> str:
    """
    Normalizuje URL (dokłada https:// jeśli brak) i sprawdza:
    - niepusty, niezbyt długi
    - dozwolony schemat (http/https)
    - poprawny host
    - host nie jest prywatnym / lokalnym IP (SSRF)
    - domena w gov.pl oraz/lub w TRUSTED_DOMAINS
    """
    raw = (raw or "").strip()
    if not raw:
        raise ValueError("Pusty adres URL")

    if len(raw) > MAX_URL_LENGTH:
        raise ValueError("Adres URL jest zbyt długi")

    # Jeśli ktoś poda np. "elblag.piw.gov.pl" – dokładamy https://
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
    if _is_private_ip(host_l):
        raise ValueError("Adres IP jest niedozwolony")

    # 2) Domena – wymagamy gov.pl i/lub obecności na liście
    no_www = host_l[4:] if host_l.startswith("www.") else host_l

    if TRUSTED_DOMAINS:
        if host_l not in TRUSTED_DOMAINS and no_www not in TRUSTED_DOMAINS:
            raise ValueError("Domena nie znajduje się na liście zaufanych gov.pl")
    else:
        # fallback: tylko *.gov.pl
        if not (host_l == "gov.pl" or host_l.endswith(".gov.pl")):
            raise ValueError("Dozwolone są tylko domeny w strefie gov.pl")

    # Zwracamy znormalizowany URL
    return parsed.geturl()


def compute_security_metadata(url: str) -> dict:
    """Zwraca podstawowe metadane bezpieczeństwa dla adresu."""
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    is_gov = host == "gov.pl" or host.endswith(".gov.pl")
    uses_https = parsed.scheme == "https"

    if TRUSTED_DOMAINS:
        no_www = host[4:] if host.startswith("www.") else host
        in_trusted = host in TRUSTED_DOMAINS or no_www in TRUSTED_DOMAINS
    else:
        in_trusted = is_gov

    return {
        "domain": host,
        "is_gov_pl": is_gov,
        "uses_https": uses_https,
        "in_trusted_list": in_trusted,
    }


def perform_tls_check(url: str):
    """
    Wykonuje realne połączenie HTTP i sprawdza TLS.
    Zwraca:
      (tls_ok, http_status, error_message)

    tls_ok:
      True  -> połączenie HTTPS z poprawnym certyfikatem
      False -> błąd TLS (np. nieprawidłowy certyfikat)
      None  -> TLS nie dotyczy (brak HTTPS) albo nie udało się sprawdzić
    """
    parsed = urlparse(url)

    # Jeśli adres NIE jest HTTPS – nie udajemy, że TLS jest OK.
    if parsed.scheme != "https":
        return None, None, "Adres nie używa HTTPS – nie sprawdzamy TLS"

    try:
        # verify=True (domyślnie) → sprawdza certyfikat wg zaufanych CA
        r = requests.get(url, timeout=5)
        return True, r.status_code, None
    except requests.exceptions.SSLError:
        # problem z certyfikatem (nieważny, self-signed, zły CN itd.)
        return False, None, "Błąd weryfikacji certyfikatu TLS/SSL"
    except requests.exceptions.RequestException:
        # host nieosiągalny, timeout itd.
        return None, None, "Nie udało się nawiązać połączenia z serwerem"


def _cleanup_sessions() -> None:
    """Usuwa stare sesje z pamięci."""
    now = time.time()
    to_delete = [
        token
        for token, sess in SESSIONS.items()
        if now - sess.get("created_at", 0) > SESSION_TTL_SECONDS * 4
    ]
    for token in to_delete:
        SESSIONS.pop(token, None)


def _get_session(token: str):
    """Zwraca sesję (albo None); aktualizuje status na 'expired' jeśli TTL minął."""
    if not token:
        return None
    sess = SESSIONS.get(token)
    if not sess:
        return None

    now = time.time()
    age = now - sess.get("created_at", 0)
    if age > SESSION_TTL_SECONDS and sess.get("status") == "pending":
        sess["status"] = "expired"

    return sess


# ---- ENDPOINT: sprawdzanie TLS dla ręcznie podanego URL ----

@app.get("/api/check-tls")
def check_tls():
    raw = request.args.get("url", "")

    try:
        url = normalize_and_validate_url(raw)
    except ValueError as e:
        return jsonify({"ok": False, "error": str(e)}), 400

    tls_ok, http_status, tls_error = perform_tls_check(url)
    meta = compute_security_metadata(url)

    payload = {
        "ok": True,
        "url": url,
        "https": meta["uses_https"],
        "http_status": http_status,
        "tls_ok": tls_ok,
        "tls_error": tls_error,
        **meta,
    }
    return jsonify(payload)


# ---- ENDPOINT: utworzenie sesji weryfikacji (nonce do QR) ----

@app.post("/api/create-session")
def create_session():
    """
    Tworzy jednorazową sesję weryfikacji:
      - waliduje URL
      - zapisuje sesję w pamięci
      - zwraca token + payload do umieszczenia w kodzie QR
    """
    data = request.get_json(silent=True) or {}
    raw_url = data.get("url") or request.form.get("url") or ""

    try:
        url = normalize_and_validate_url(raw_url)
    except ValueError as e:
        return jsonify({"ok": False, "error": str(e)}), 400

    _cleanup_sessions()

    token = secrets.token_urlsafe(16)
    now = time.time()

    SESSIONS[token] = {
        "token": token,
        "url": url,
        "created_at": now,
        "status": "pending",      # pending / confirmed / rejected / expired
        "verdict": None,          # True / False / None
        "verdict_reason": None,
    }

    # W praktyce ten adres byłby np. specjalnym URL-em rozumianym przez mObywatel.
    base = request.host_url.rstrip("/")
    qr_payload = f"{base}/verify?token={token}"

    return jsonify({
        "ok": True,
        "token": token,
        "url": url,
        "qr_payload": qr_payload,
        "expires_in": SESSION_TTL_SECONDS,
    })


# ---- ENDPOINT: potwierdzenie sesji (wywoływany przez mObywatel / nasz skaner) ----

@app.post("/api/confirm-session")
def confirm_session():
    """
    Potwierdzenie sesji przez zaufanego klienta (np. aplikację mObywatel).
    W prototypie nie walidujemy tożsamości klienta – to byłby temat na mTLS/podpisy.
    """
    data = request.get_json(silent=True) or {}
    token = data.get("token") or request.args.get("token") or ""

    sess = _get_session(token)
    if not sess:
        return jsonify({"ok": False, "error": "Sesja nie istnieje lub wygasła"}), 404

    if sess["status"] in ("confirmed", "rejected", "expired"):
        return jsonify({
            "ok": False,
            "error": f"Sesja ma już status: {sess['status']}",
            "status": sess["status"],
        }), 400

    url = sess["url"]

    # Sprawdzamy parametry bezpieczeństwa w momencie potwierdzenia
    meta = compute_security_metadata(url)
    tls_ok, http_status, tls_error = perform_tls_check(url)

    # Prosta logika werdyktu – można rozbudować
    verdict = bool(
        meta["is_gov_pl"]
        and meta["in_trusted_list"]
        and (tls_ok is True or (tls_ok is None and meta["uses_https"]))
    )

    if verdict:
        sess["status"] = "confirmed"
        sess["verdict"] = True
        sess["verdict_reason"] = "Domena gov.pl z listy zaufanych, poprawny TLS"
    else:
        sess["status"] = "rejected"
        sess["verdict"] = False
        reasons = []
        if not meta["is_gov_pl"]:
            reasons.append("Domena nie jest w strefie gov.pl")
        if not meta["in_trusted_list"]:
            reasons.append("Domena nie znajduje się na liście zaufanych")
        if tls_ok is False:
            reasons.append("Błąd weryfikacji certyfikatu TLS/SSL")
        if tls_ok is None:
            reasons.append("Nie udało się potwierdzić stanu TLS/SSL")
        sess["verdict_reason"] = (
            "; ".join(reasons) or "Nie spełnia kryteriów zaufania"
        )

    response = {
        "ok": True,
        "token": token,
        "url": url,
        "status": sess["status"],
        "verdict": sess["verdict"],
        "verdict_reason": sess["verdict_reason"],
        "http_status": http_status,
        "tls_ok": tls_ok,
        "tls_error": tls_error,
        **meta,
    }
    return jsonify(response)


# ---- ENDPOINT: status sesji (polling przez stronę www) ----

@app.get("/api/session-status")
def session_status():
    """
    Zwraca aktualny status sesji:
      pending / confirmed / rejected / expired
    oraz (jeśli dostępne) werdykt i powód.
    """
    token = request.args.get("token") or request.args.get("session_id") or ""

    sess = _get_session(token)
    if not sess:
        return jsonify({
            "ok": False,
            "error": "Sesja nie istnieje lub wygasła",
            "status": "not_found",
        }), 404

    now = time.time()
    age = now - sess.get("created_at", 0)
    ttl_left = max(0, SESSION_TTL_SECONDS - int(age))

    return jsonify({
        "ok": True,
        "token": token,
        "url": sess["url"],
        "status": sess["status"],
        "verdict": sess["verdict"],
        "verdict_reason": sess["verdict_reason"],
        "expires_in": ttl_left,
    })


# ---- FRONT (statyczna strona) ----

@app.route("/")
def index():
    return app.send_static_file("index.html")


if __name__ == "__main__":
    app.run(debug=True)
