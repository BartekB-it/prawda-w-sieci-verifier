// script.js

// URL do pliku z listą zaufanych domen (whitelist)
const DOMAINS_JSON_URL = "domains.json";

let trustedDomains = null;      // Set z domenami z domains.json
let trustedLoaded = false;
let trustedLoadingError = null;

// ---- ŁADOWANIE LISTY DOMEN Z JSON ----
async function loadTrustedDomains() {
    const response = await fetch(DOMAINS_JSON_URL);
    if (!response.ok) {
        throw new Error(`Nie udało się pobrać ${DOMAINS_JSON_URL} (status ${response.status})`);
    }

    const domains = await response.json();

    const set = new Set();
    for (const d of domains) {
        const domain = String(d).trim().toLowerCase();
        if (domain) {
            set.add(domain);
        }
    }
    return set;
}

async function ensureTrustedLoaded() {
    if (trustedLoaded && trustedDomains) {
        return trustedDomains;
    }
    if (trustedLoadingError) {
        throw trustedLoadingError;
    }

    try {
        const set = await loadTrustedDomains();
        trustedDomains = set;
        trustedLoaded = true;
        return trustedDomains;
    } catch (err) {
        trustedLoadingError = err;
        throw err;
    }
}

// ---- POMOCNICZE FUNKCJE URL ----
function parseUrl(input) {
    let value = input.trim();
    if (!value) {
        throw new Error("Pusty adres URL");
    }

    // Jeśli user poda np. "ai.gov.pl" bez schematu – załóżmy domyślnie HTTPS
    if (!/^https?:\/\//i.test(value)) {
        value = "https://" + value;
    }

    return new URL(value);
}

// Czy domena jest w strefie gov.pl (np. gov.pl, ai.gov.pl, elblag.piw.gov.pl)
function isGovPlDomain(domain) {
    domain = domain.toLowerCase();
    return domain === "gov.pl" || domain.endsWith(".gov.pl");
}

// Czy adres używa HTTPS (co dla nas = "ma SSL/TLS" na poziomie samego URL)
function isTls(urlObj) {
    return urlObj.protocol === "https:";
}

// Sprawdza, czy domena lub wersja bez 'www.' jest na liście zaufanych
function isInTrustedDomains(domain, trustedSet) {
    const d = domain.toLowerCase();
    const noWww = d.startsWith("www.") ? d.slice(4) : d;
    return trustedSet.has(d) || trustedSet.has(noWww);
}

// ---- SPRAWDZANIE TLS PO STRONIE BACKENDU ----
// Wymaga endpointu /api/check-tls?url=... zwracającego JSON
// np. { ok: true, tls_ok: true/false, error?: "..." }
async function checkTlsOnBackend(url) {
    const resp = await fetch(`/api/check-tls?url=${encodeURIComponent(url)}`);
    const data = await resp.json();
    return data;
}

// ---- GŁÓWNA FUNKCJA SPRAWDZAJĄCA (ASYNC!) ----
async function checkUrl(input) {
    try {
        const urlObj = parseUrl(input);
        const domain = urlObj.hostname.toLowerCase();

        // --- WHITELISTA DOMEN (domains.json) ---
        let isTrusted = null;
        let trustedErrorMsg = null;
        try {
            const trustedSet = await ensureTrustedLoaded();
            isTrusted = isInTrustedDomains(domain, trustedSet);
        } catch (err) {
            trustedErrorMsg = err.message || "Nie udało się wczytać listy domains.json";
        }

        // --- TLS po stronie backendu ---
        let backendTls = null;
        let backendTlsError = null;
        try {
            const tlsResult = await checkTlsOnBackend(urlObj.href);
            if (tlsResult && tlsResult.ok === true) {
                backendTls = tlsResult.tls_ok === true;
            } else {
                backendTls = null;
                backendTlsError = (tlsResult && tlsResult.error)
                    ? tlsResult.error
                    : "Nieprawidłowa odpowiedź z serwera TLS";
            }
        } catch (e) {
            backendTlsError = e.message || "Błąd sprawdzania TLS po stronie serwera";
        }

        return {
            ok: true,
            domain,
            isGovPl: isGovPlDomain(domain),
            isTls: isTls(urlObj),        // HTTPS w URL
            isTrusted,                   // true / false / null
            trustedErrorMsg,
            backendTls,                  // true / false / null
            backendTlsError
        };
    } catch (e) {
        return {
            ok: false,
            error: e.message || "Nieprawidłowy adres URL"
        };
    }
}

// ---- RENDER WYNIKU ----
function renderResult(result) {
    const resultsDiv = document.getElementById("results");

    if (!result.ok) {
        resultsDiv.innerHTML = `<p class="error">${result.error}</p>`;
        return;
    }

    const govClass = result.isGovPl ? "result-ok" : "result-bad";
    const tlsSchemeClass = result.isTls ? "result-ok" : "result-bad";

    // Linia o TLS z backendu
    let backendTlsLine = "";
    if (result.backendTls === true) {
        backendTlsLine = `
            <li class="result-ok">
                Certyfikat TLS/SSL zweryfikowany po stronie serwera: <strong>OK</strong>
            </li>
        `;
    } else if (result.backendTls === false) {
        backendTlsLine = `
            <li class="result-bad">
                Problem z certyfikatem TLS/SSL (backend): <strong>BŁĄD</strong>
                ${result.backendTlsError ? `(<em>${result.backendTlsError}</em>)` : ""}
            </li>
        `;
    } else if (result.backendTlsError) {
        backendTlsLine = `
            <li class="result-bad">
                Nie udało się zweryfikować certyfikatu TLS po stronie serwera
                ${result.backendTlsError ? `(<em>${result.backendTlsError}</em>)` : ""}
            </li>
        `;
    }

    // Linia o białej liście (domains.json)
    let trustedLine = "";
    if (result.isTrusted === true) {
        trustedLine = `
            <li class="result-ok">
                Na liście oficjalnych domen (domains.json): <strong>TAK</strong>
            </li>
        `;
    } else if (result.isTrusted === false) {
        trustedLine = `
            <li class="result-bad">
                Na liście oficjalnych domen (domains.json): <strong>NIE</strong>
            </li>
        `;
    } else {
        trustedLine = `
            <li class="result-bad">
                Nie udało się sprawdzić w domains.json
                ${result.trustedErrorMsg ? `(<em>${result.trustedErrorMsg}</em>)` : ""}
            </li>
        `;
    }

    // Podsumowanie ogólne: pozytywne / ostrzeżenie
    let summaryHtml = "";
    const looksTrusted =
        result.isGovPl &&
        (result.backendTls === true || (result.backendTls === null && result.isTls)) &&
        result.isTrusted === true;

    if (looksTrusted) {
        summaryHtml = `
            <p class="summary summary-ok">
                Strona wygląda na <strong>zaufaną</strong> wg dostępnych kryteriów
                (domena gov.pl, HTTPS, biała lista). Mimo to zawsze zweryfikuj,
                czy adres jest dokładnie tym, którego oczekujesz.
            </p>
        `;
    } else {
        summaryHtml = `
            <p class="summary summary-warn">
                Uwaga: nie wszystkie kryteria bezpieczeństwa są spełnione.
                Traktuj stronę jako potencjalnie niezaufaną, nie podawaj danych
                i zweryfikuj adres w aplikacji mObywatel lub na oficjalnej liście serwisów gov.pl.
            </p>
        `;
    }

    resultsDiv.innerHTML = `
        <p><strong>Domena:</strong> ${result.domain}</p>
        <ul>
            <li class="${govClass}">
                Domena rządowa (.gov.pl): <strong>${result.isGovPl ? "TAK" : "NIE"}</strong>
            </li>
            <li class="${tlsSchemeClass}">
                Adres używa HTTPS (w URL): <strong>${result.isTls ? "TAK" : "NIE"}</strong>
            </li>
            ${backendTlsLine || ""}
            ${trustedLine}
        </ul>
        ${summaryHtml}
    `;
}

// ---- OBSŁUGA SKANERA QR ----
let qrScanner = null;
let qrScanning = false;

async function startQrScanner() {
    const qrSection = document.getElementById("qr-section");
    const qrReaderElem = document.getElementById("qr-reader");
    const resultsDiv = document.getElementById("results");

    if (!qrSection || !qrReaderElem) return;

    qrSection.classList.remove("hidden");

    if (!window.Html5Qrcode) {
        resultsDiv.innerHTML = `<p class="error">
            Skaner QR nie jest dostępny (brak biblioteki html5-qrcode).
        </p>`;
        return;
    }

    if (qrScanning) {
        // Już skanujemy – nie uruchamiaj drugi raz
        return;
    }

    qrScanner = new Html5Qrcode("qr-reader");
    qrScanning = true;

    try {
        await qrScanner.start(
            { facingMode: "environment" },
            { fps: 10, qrbox: 250 },
            async (decodedText /*, decodedResult */) => {
                // Po odczycie pierwszego kodu – zatrzymujemy skanowanie
                stopQrScanner();

                const input = document.getElementById("url-input");
                if (input) {
                    input.value = decodedText;
                }

                const resultsDiv = document.getElementById("results");
                resultsDiv.innerHTML = "<p>Odebrano adres z kodu QR. Sprawdzam...</p>";

                const result = await checkUrl(decodedText);
                renderResult(result);
            },
            (errorMessage) => {
                // Błędy pojedynczych klatek ignorujemy (szum z kamery)
            }
        );
    } catch (err) {
        qrScanning = false;
        resultsDiv.innerHTML = `<p class="error">
            Nie udało się uruchomić skanera QR: ${err}
        </p>`;
    }
}

function stopQrScanner() {
    const qrSection = document.getElementById("qr-section");
    if (qrSection) {
        qrSection.classList.add("hidden");
    }

    if (qrScanner) {
        qrScanner.stop()
            .then(() => {
                qrScanner.clear();
                qrScanner = null;
                qrScanning = false;
            })
            .catch(() => {
                qrScanner = null;
                qrScanning = false;
            });
    } else {
        qrScanning = false;
    }
}

// ---- PODPIĘCIE DO HTML (ASYNCHRONICZNY CLICK) ----
document.addEventListener("DOMContentLoaded", () => {
    const input = document.getElementById("url-input");
    const btn = document.getElementById("check-btn");
    const resultsDiv = document.getElementById("results");
    const qrBtn = document.getElementById("qr-btn");
    const qrStopBtn = document.getElementById("qr-stop-btn");
    const qrBannerBtn = document.getElementById("qr-banner-btn");

    // RĘCZNE SPRAWDZANIE
    if (btn) {
        btn.addEventListener("click", async () => {
            const value = input.value;
            resultsDiv.innerHTML = "<p>Sprawdzam adres.</p>";

            const result = await checkUrl(value);
            renderResult(result);
        });
    }

    // Enter w polu = kliknięcie przycisku (bez Shift, żeby nie łamać linii)
    if (input) {
        input.addEventListener("keydown", (event) => {
            if (event.key === "Enter" && !event.shiftKey) {
                event.preventDefault();
                if (btn) {
                    btn.click();
                }
            }
        });
    }

    // PRZYCISK „SKANUJ KOD QR” W DOLNYM PASKU
    if (qrBtn) {
        qrBtn.addEventListener("click", (event) => {
            event.preventDefault();
            startQrScanner();
        });
    }

    // LINK/PRZYCISK „Zeskanuj kod QR” W NIEBIESKIM BANERZE
    if (qrBannerBtn) {
        qrBannerBtn.addEventListener("click", (event) => {
            event.preventDefault();
            startQrScanner();
        });
    }

    // PRZYCISK „ZATRZYMAJ SKANOWANIE”
    if (qrStopBtn) {
        qrStopBtn.addEventListener("click", (event) => {
            event.preventDefault();
            stopQrScanner();
        });
    }

    // AKORDEON "Informacje o bezpieczeństwie"
    const securityToggle = document.getElementById("security-toggle");
    const securityContent = document.getElementById("security-content");

    if (securityToggle && securityContent) {
        securityToggle.addEventListener("click", () => {
            const expanded = securityToggle.getAttribute("aria-expanded") === "true";
            securityToggle.setAttribute("aria-expanded", String(!expanded));
            securityContent.hidden = expanded;
        });
    }
});
