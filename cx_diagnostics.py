import os
import ssl
import json
import socket
import urllib.parse
from datetime import datetime

import requests
from requests.exceptions import (
    SSLError,
    ProxyError,
    ConnectTimeout,
    ReadTimeout,
    ConnectionError,
    RequestException,
)


CX_BASE_URL = os.getenv("CX_BASE_URL", "https://acpckmapp04.profuturo-gnp.net")
CX_USERNAME = os.getenv("CX_USERNAME")
CX_PASSWORD = os.getenv("CX_PASSWORD")

CX_CLIENT_ID = os.getenv("CX_CLIENT_ID", "resource_owner_client")
CX_CLIENT_SECRET = os.getenv(
    "CX_CLIENT_SECRET",
    "014DF517-39D1-4453-B7B3-9930C563627C",
)

# Para diagnóstico puede ser "false".
# Para productivo, usar un CA bundle corporativo.
# Ejemplo:
# CX_VERIFY_TLS=/path/to/corporate_ca.pem
CX_VERIFY_TLS_RAW = os.getenv("CX_VERIFY_TLS", "false").strip().lower()

if CX_VERIFY_TLS_RAW in ("false", "0", "no"):
    VERIFY_TLS = False
elif CX_VERIFY_TLS_RAW in ("true", "1", "yes"):
    VERIFY_TLS = True
else:
    # Ruta a un certificado CA corporativo
    VERIFY_TLS = CX_VERIFY_TLS_RAW


TIMEOUT_SECONDS = int(os.getenv("CX_TIMEOUT_SECONDS", "20"))


def section(title: str):
    print("\n" + "=" * 90)
    print(title)
    print("=" * 90)


def print_kv(key, value):
    print(f"{key:<28}: {value}")


def parse_base_url():
    parsed = urllib.parse.urlparse(CX_BASE_URL)

    scheme = parsed.scheme or "https"
    host = parsed.hostname
    port = parsed.port

    if not host:
        raise ValueError(f"CX_BASE_URL inválida: {CX_BASE_URL}")

    if port is None:
        port = 443 if scheme == "https" else 80

    return scheme, host, port


def get_runner_public_ip():
    section("1. Public IP del runner")

    urls = [
        "https://api.ipify.org",
        "https://ifconfig.me/ip",
    ]

    for url in urls:
        try:
            response = requests.get(url, timeout=10)
            if response.ok:
                print_kv("Public IP", response.text.strip())
                return
        except Exception as exc:
            print_kv(f"Fallo consultando {url}", repr(exc))

    print("No se pudo obtener IP pública del runner.")


def print_environment():
    section("2. Ambiente del runner")

    safe_vars = [
        "GITHUB_ACTIONS",
        "RUNNER_OS",
        "RUNNER_ARCH",
        "RUNNER_NAME",
        "RUNNER_ENVIRONMENT",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "NO_PROXY",
        "CX_BASE_URL",
        "CX_VERIFY_TLS",
    ]

    for var in safe_vars:
        value = os.getenv(var)
        if value:
            print_kv(var, value)
        else:
            print_kv(var, "<no definido>")


def dns_check(host):
    section("3. DNS check")

    print_kv("Host", host)

    try:
        results = socket.getaddrinfo(host, None)
        ips = sorted({item[4][0] for item in results})

        if not ips:
            print("DNS resolvió, pero no devolvió IPs.")
            return False

        for ip in ips:
            print_kv("Resolved IP", ip)

        private_hint = any(
            ip.startswith(("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                           "172.20.", "172.21.", "172.22.", "172.23.",
                           "172.24.", "172.25.", "172.26.", "172.27.",
                           "172.28.", "172.29.", "172.30.", "172.31.",
                           "192.168."))
            for ip in ips
        )

        if private_hint:
            print(
                "\nObservación: el host parece resolver a una IP privada. "
                "Desde un runner cloud probablemente hará falta VPN, proxy, "
                "peering, private networking o self-hosted runner dentro de la red."
            )

        return True

    except socket.gaierror as exc:
        print("FALLO DNS.")
        print_kv("Error", repr(exc))
        print(
            "\nInterpretación probable: el DNS corporativo no está disponible "
            "desde GitHub Actions, el dominio es interno, o hace falta VPN/proxy DNS."
        )
        return False


def tcp_check(host, port):
    section("4. TCP connectivity check")

    print_kv("Host", host)
    print_kv("Port", port)

    try:
        with socket.create_connection((host, port), timeout=TIMEOUT_SECONDS):
            print("TCP OK: el runner pudo abrir conexión al host/puerto.")
            return True

    except socket.timeout as exc:
        print("FALLO TCP: timeout.")
        print_kv("Error", repr(exc))
        print(
            "\nInterpretación probable: firewall, ruta inexistente, VPN faltante, "
            "puerto no expuesto o bloqueo por origen."
        )
        return False

    except OSError as exc:
        print("FALLO TCP.")
        print_kv("Error", repr(exc))
        print(
            "\nInterpretación probable: no hay ruta de red, el puerto está cerrado, "
            "o el host no es alcanzable desde el runner."
        )
        return False


def tls_check(host, port):
    section("5. TLS handshake check")

    try:
        context = ssl.create_default_context()

        with socket.create_connection((host, port), timeout=TIMEOUT_SECONDS) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()

                print("TLS OK: handshake exitoso.")
                print_kv("TLS version", ssock.version())
                print_kv("Cipher", ssock.cipher())

                subject = cert.get("subject", [])
                issuer = cert.get("issuer", [])
                not_before = cert.get("notBefore")
                not_after = cert.get("notAfter")

                print_kv("Certificate subject", subject)
                print_kv("Certificate issuer", issuer)
                print_kv("Valid from", not_before)
                print_kv("Valid until", not_after)

                return True

    except ssl.SSLCertVerificationError as exc:
        print("FALLO TLS: certificado no confiable para el runner.")
        print_kv("Error", repr(exc))
        print(
            "\nInterpretación probable: hace falta instalar/usar el certificado "
            "CA corporativo en el runner o pasar un bundle mediante CX_VERIFY_TLS."
        )
        return False

    except Exception as exc:
        print("FALLO TLS.")
        print_kv("Error", repr(exc))
        return False


def http_probe(path="/cxrestapi"):
    section("6. HTTP probe básico")

    url = f"{CX_BASE_URL.rstrip('/')}{path}"

    print_kv("URL", url)
    print_kv("VERIFY_TLS", VERIFY_TLS)

    try:
        response = requests.get(
            url,
            timeout=TIMEOUT_SECONDS,
            verify=VERIFY_TLS,
            headers={
                "Accept": "application/json, text/plain, */*",
                "cxOrigin": "github-actions-diagnostic",
            },
        )

        print_kv("Status", response.status_code)
        print_kv("Reason", response.reason)
        print_kv("Final URL", response.url)
        print_kv("Content-Type", response.headers.get("Content-Type"))

        body_preview = response.text[:1000] if response.text else "<sin body>"
        print_kv("Body preview", body_preview)

        return response.status_code

    except SSLError as exc:
        print("FALLO HTTP/TLS.")
        print_kv("Error", repr(exc))
        print(
            "\nInterpretación probable: certificado corporativo no confiable "
            "desde el runner."
        )
        return None

    except ProxyError as exc:
        print("FALLO PROXY.")
        print_kv("Error", repr(exc))
        print(
            "\nInterpretación probable: proxy mal configurado, proxy no alcanzable "
            "desde GitHub Actions, o credenciales de proxy faltantes."
        )
        return None

    except ConnectTimeout as exc:
        print("FALLO HTTP: connect timeout.")
        print_kv("Error", repr(exc))
        print(
            "\nInterpretación probable: red/firewall/VPN/ruta. El runner no puede "
            "llegar al servicio."
        )
        return None

    except ReadTimeout as exc:
        print("FALLO HTTP: read timeout.")
        print_kv("Error", repr(exc))
        print(
            "\nInterpretación probable: el servicio acepta conexión pero no responde "
            "a tiempo, o hay inspección/proxy intermedio."
        )
        return None

    except ConnectionError as exc:
        print("FALLO HTTP: connection error.")
        print_kv("Error", repr(exc))
        print(
            "\nInterpretación probable: DNS, firewall, ruta, puerto cerrado, "
            "VPN faltante o reset por dispositivo intermedio."
        )
        return None

    except RequestException as exc:
        print("FALLO HTTP genérico.")
        print_kv("Error", repr(exc))
        return None


def debug_response(response):
    print_kv("Status", response.status_code)
    print_kv("Reason", response.reason)
    print_kv("URL", response.url)
    print_kv("Content-Type", response.headers.get("Content-Type"))

    try:
        print("Body JSON:")
        print(json.dumps(response.json(), indent=2, ensure_ascii=False))
    except Exception:
        print("Body Text:")
        print(response.text[:2000])


def get_token():
    section("7. Token test")

    if not CX_USERNAME or not CX_PASSWORD:
        print(
            "CX_USERNAME/CX_PASSWORD no están definidos. "
            "Se omite prueba de autenticación."
        )
        return None

    url = f"{CX_BASE_URL.rstrip('/')}/cxrestapi/auth/identity/connect/token"

    payload = {
        "username": CX_USERNAME,
        "password": CX_PASSWORD,
        "grant_type": "password",
        "scope": "sast_rest_api",
        "client_id": CX_CLIENT_ID,
        "client_secret": CX_CLIENT_SECRET,
    }

    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
        "cxOrigin": "github-actions-diagnostic",
    }

    try:
        response = requests.post(
            url,
            data=payload,
            headers=headers,
            timeout=TIMEOUT_SECONDS,
            verify=VERIFY_TLS,
        )

        if not response.ok:
            print("FALLO TOKEN.")
            debug_response(response)
            return None

        data = response.json()
        token = data.get("access_token")

        if not token:
            print("La respuesta no contiene access_token.")
            print(json.dumps(data, indent=2, ensure_ascii=False))
            return None

        print("TOKEN OK: access_token obtenido correctamente.")
        print_kv("Token length", len(token))
        return token

    except Exception as exc:
        print("FALLO TOKEN por excepción.")
        print_kv("Error", repr(exc))
        return None


def get_projects(token):
    section("8. Projects API test")

    if not token:
        print("Sin token. Se omite consulta de proyectos.")
        return None

    url = f"{CX_BASE_URL.rstrip('/')}/cxrestapi/projects"

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json;v=1.0",
        "cxOrigin": "github-actions-diagnostic",
    }

    try:
        response = requests.get(
            url,
            headers=headers,
            timeout=TIMEOUT_SECONDS,
            verify=VERIFY_TLS,
        )

        if not response.ok:
            print("FALLO PROJECTS.")
            debug_response(response)
            return None

        data = response.json()

        if isinstance(data, list):
            print_kv("Projects count", len(data))
        else:
            print("Respuesta recibida, pero no es lista.")
            print(json.dumps(data, indent=2, ensure_ascii=False)[:2000])

        print("PROJECTS OK.")
        return data

    except Exception as exc:
        print("FALLO PROJECTS por excepción.")
        print_kv("Error", repr(exc))
        return None


def final_recommendation(dns_ok, tcp_ok, tls_ok, token):
    section("9. Diagnóstico resumido")

    print_kv("DNS", "OK" if dns_ok else "FAIL")
    print_kv("TCP", "OK" if tcp_ok else "FAIL")
    print_kv("TLS", "OK" if tls_ok else "FAIL")
    print_kv("TOKEN", "OK" if token else "SKIPPED/FAIL")

    print("\nLectura rápida:")

    if not dns_ok:
        print(
            "- Pide a infraestructura resolver DNS corporativo desde el runner, "
            "VPN, proxy DNS o usar self-hosted runner dentro de la red."
        )
    elif dns_ok and not tcp_ok:
        print(
            "- DNS funciona, pero no hay conectividad al puerto. Pide revisión de "
            "firewall, rutas, VPN, allowlist de origen o exposición controlada."
        )
    elif tcp_ok and not tls_ok:
        print(
            "- Hay red, pero falla confianza TLS. Pide el certificado CA corporativo "
            "o configura el trust store del runner."
        )
    elif tls_ok and not token:
        print(
            "- La red parece funcionar. El problema puede estar en credenciales, "
            "endpoint, permisos, client_id/client_secret o configuración REST de CxSAST."
        )
    else:
        print(
            "- El runner puede llegar a Checkmarx y autenticarse. Ya puedes avanzar "
            "a integración real del flujo CI/CD."
        )

    print("\nOpciones típicas si es on-premise:")
    print("- Self-hosted runner dentro de la red corporativa.")
    print("- VPN desde runner hacia red corporativa.")
    print("- Proxy corporativo accesible desde GitHub Actions.")
    print("- Larger runner con IP estática + firewall allowlist.")
    print("- API Gateway/reverse proxy corporativo con autenticación fuerte.")


def main():
    section("0. Checkmarx CxSAST connectivity diagnostic")
    print_kv("Timestamp UTC", datetime.utcnow().isoformat() + "Z")
    print_kv("CX_BASE_URL", CX_BASE_URL)

    scheme, host, port = parse_base_url()

    print_kv("Scheme", scheme)
    print_kv("Host", host)
    print_kv("Port", port)

    get_runner_public_ip()
    print_environment()

    dns_ok = dns_check(host)
    tcp_ok = tcp_check(host, port) if dns_ok else False
    tls_ok = tls_check(host, port) if tcp_ok and scheme == "https" else False

    # Probe simple del servidor. Puede fallar con 401/404 y aun así ser útil:
    # lo importante es distinguir error de red vs respuesta HTTP real.
    http_probe("/cxrestapi")

    token = get_token()
    get_projects(token)

    final_recommendation(dns_ok, tcp_ok, tls_ok, token)


if __name__ == "__main__":
    main()