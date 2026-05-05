import argparse
import os
import socket
import sys
from typing import Any
from urllib.parse import urlparse

import requests
import urllib3


DEFAULT_CX_BASE_URL = "https://acpckmapp04.profuturo-gnp.net"
DEFAULT_CLIENT_ID = "resource_owner_client"
DEFAULT_SCOPE = "sast_rest_api"


def get_required_env(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"Falta variable de entorno requerida: {name}")
    return value


def parse_verify_tls(value: str | None) -> bool | str:
    """
    CX_VERIFY_TLS puede ser:
      - true / 1 / yes  -> verifica TLS con certificados del sistema
      - false / 0 / no  -> desactiva verificación TLS, solo diagnóstico
      - /ruta/ca.pem    -> usa CA corporativa
    """
    if value is None or value.strip() == "":
        return True

    normalized = value.strip().lower()

    if normalized in {"true", "1", "yes", "y"}:
        return True

    if normalized in {"false", "0", "no", "n"}:
        return False

    return value.strip()


def debug_response(response: requests.Response) -> None:
    print("Status:", response.status_code)
    print("Reason:", response.reason)
    print("URL:", response.url)
    print("Content-Type:", response.headers.get("Content-Type"))

    try:
        print("Body JSON:", response.json())
    except Exception:
        print("Body Text:", response.text[:2000])


def validate_network(cx_base_url: str, timeout: int) -> None:
    parsed = urlparse(cx_base_url)

    if not parsed.scheme or not parsed.hostname:
        raise RuntimeError(f"CX_BASE_URL inválida: {cx_base_url}")

    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    print(f"Network check host={host} port={port}")

    try:
        resolved = socket.gethostbyname_ex(host)
        print("DNS OK:", resolved)
    except Exception as exc:
        raise RuntimeError(f"DNS FAIL para {host}: {exc}") from exc

    try:
        with socket.create_connection((host, port), timeout=timeout):
            print("TCP OK")
    except Exception as exc:
        raise RuntimeError(f"TCP FAIL hacia {host}:{port}: {exc}") from exc


def build_session() -> requests.Session:
    session = requests.Session()

    # True: requests toma HTTP_PROXY, HTTPS_PROXY, NO_PROXY del ambiente.
    # False: ignora proxies del ambiente.
    trust_env = os.getenv("CX_TRUST_ENV", "true").strip().lower()
    session.trust_env = trust_env not in {"false", "0", "no", "n"}

    print("Requests trust_env:", session.trust_env)
    print("HTTPS_PROXY configured:", bool(os.getenv("HTTPS_PROXY") or os.getenv("https_proxy")))
    print("NO_PROXY:", os.getenv("NO_PROXY") or os.getenv("no_proxy") or "")

    return session


def get_token(
    session: requests.Session,
    cx_base_url: str,
    username: str,
    password: str,
    client_secret: str,
    verify_tls: bool | str,
    timeout: int,
) -> str:
    url = f"{cx_base_url.rstrip('/')}/cxrestapi/auth/identity/connect/token"

    payload = {
        "username": username,
        "password": password,
        "grant_type": "password",
        "scope": DEFAULT_SCOPE,
        "client_id": DEFAULT_CLIENT_ID,
        "client_secret": client_secret,
    }

    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
        "cxOrigin": os.getenv("CX_ORIGIN", "github-actions"),
    }

    response = session.post(
        url,
        data=payload,
        headers=headers,
        timeout=timeout,
        verify=verify_tls,
    )

    if not response.ok:
        debug_response(response)
        raise RuntimeError("Falló la obtención del token.")

    data = response.json()

    if "access_token" not in data:
        raise RuntimeError(f"La respuesta no contiene access_token. Keys recibidas: {list(data.keys())}")

    return data["access_token"]


def get_projects(
    session: requests.Session,
    cx_base_url: str,
    token: str,
    verify_tls: bool | str,
    timeout: int,
) -> Any:
    url = f"{cx_base_url.rstrip('/')}/cxrestapi/projects"

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json;v=1.0",
        "cxOrigin": os.getenv("CX_ORIGIN", "github-actions"),
    }

    response = session.get(
        url,
        headers=headers,
        timeout=timeout,
        verify=verify_tls,
    )

    if not response.ok:
        debug_response(response)
        raise RuntimeError("Falló la consulta de proyectos.")

    return response.json()


def summarize_projects(projects: Any, print_projects: bool) -> None:
    print("Token obtenido correctamente")

    if isinstance(projects, list):
        print("Total proyectos:", len(projects))

        if print_projects:
            print("Primeros proyectos:")
            for project in projects[:20]:
                if isinstance(project, dict):
                    print(
                        {
                            "id": project.get("id"),
                            "name": project.get("name"),
                            "teamId": project.get("teamId"),
                        }
                    )
                else:
                    print(project)
    else:
        print("Respuesta de proyectos no es lista.")
        print(type(projects))
        if print_projects:
            print(projects)


def main() -> int:
    parser = argparse.ArgumentParser(description="Prueba de conexión a Checkmarx SAST REST API.")
    parser.add_argument("--skip-network-check", action="store_true")
    parser.add_argument("--print-projects", action="store_true")
    args = parser.parse_args()

    cx_base_url = os.getenv("CX_BASE_URL", DEFAULT_CX_BASE_URL).rstrip("/")
    username = get_required_env("CX_USERNAME")
    password = get_required_env("CX_PASSWORD")
    client_secret = os.getenv(
        "CX_CLIENT_SECRET",
        "014DF517-39D1-4453-B7B3-9930C563627C",
    )

    timeout = int(os.getenv("CX_TIMEOUT", "30"))
    verify_tls = parse_verify_tls(os.getenv("CX_VERIFY_TLS"))

    if verify_tls is False:
        print("WARNING: TLS verification está desactivado. Usar solo para diagnóstico.")
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    print("CX_BASE_URL:", cx_base_url)
    print("VERIFY_TLS:", verify_tls if verify_tls is not True else "true")

    if not args.skip_network_check:
        validate_network(cx_base_url, timeout=timeout)

    session = build_session()

    token = get_token(
        session=session,
        cx_base_url=cx_base_url,
        username=username,
        password=password,
        client_secret=client_secret,
        verify_tls=verify_tls,
        timeout=timeout,
    )

    projects = get_projects(
        session=session,
        cx_base_url=cx_base_url,
        token=token,
        verify_tls=verify_tls,
        timeout=timeout,
    )

    summarize_projects(projects, print_projects=args.print_projects)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)