"""
JWTLab CLI — three commands: serve, analyze, crack.
No AI dependency. Normative contract per app_spec.txt §cli_interface.
"""
from __future__ import annotations

import json
import sys
from typing import Optional

import typer
from rich.console import Console

app = typer.Typer(
    name="jwtlab",
    help="JWTLab — Interactive JWT Attack Visualizer",
    add_completion=False,
)
console = Console()
err_console = Console(stderr=True)


# ─── jwtlab serve ─────────────────────────────────────────────────────────────

@app.command("serve")
def serve(
    port: int = typer.Option(8765, "--port", help="TCP port to listen on"),
    host: str = typer.Option("127.0.0.1", "--host", help="Bind address; non-loopback triggers warning"),
) -> None:
    """Start the FastAPI backend and serve the pre-bundled React frontend."""
    loopback = {"127.0.0.1", "::1", "localhost"}
    if host not in loopback:
        console.print(
            "[bold red]WARNING[/bold red]: JWTLab is exposing intentionally vulnerable "
            "endpoints on a non-loopback interface. This is unsafe on shared networks."
        )

    # Probe the port before handing off to uvicorn so OSError stays Python-visible
    import socket
    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        probe.bind((host if host != "localhost" else "127.0.0.1", port))
        probe.close()
    except OSError:
        err_console.print(f"ERROR: port {port} is already in use. Choose another with --port.")
        raise SystemExit(1)

    # Log config: redirect all uvicorn output to stdout so callers can capture it
    _log_config = {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "default": {
                "()": "uvicorn.logging.DefaultFormatter",
                "fmt": "%(levelprefix)s %(message)s",
                "use_colors": None,
            },
            "access": {
                "()": "uvicorn.logging.AccessFormatter",
                "fmt": '%(levelprefix)s %(client_addr)s - "%(request_line)s" %(status_code)s',
            },
        },
        "handlers": {
            "default": {
                "formatter": "default",
                "class": "logging.StreamHandler",
                "stream": "ext://sys.stdout",
            },
            "access": {
                "formatter": "access",
                "class": "logging.StreamHandler",
                "stream": "ext://sys.stdout",
            },
        },
        "loggers": {
            "uvicorn": {"handlers": ["default"], "level": "INFO", "propagate": False},
            "uvicorn.error": {"handlers": ["default"], "level": "INFO", "propagate": False},
            "uvicorn.access": {"handlers": ["access"], "level": "INFO", "propagate": False},
        },
    }

    try:
        import uvicorn
        from jwtlab.server import create_app
        application = create_app()
        uvicorn.run(application, host=host, port=port, log_level="info", log_config=_log_config)
    except KeyboardInterrupt:
        raise SystemExit(0)
    except OSError as exc:
        if "address already in use" in str(exc).lower() or "only one usage" in str(exc).lower():
            err_console.print(f"ERROR: port {port} is already in use. Choose another with --port.")
        else:
            err_console.print(f"ERROR: could not bind to {host}:{port} — {exc}")
        raise SystemExit(1)
    except ImportError as exc:
        err_console.print(f"ERROR: failed to import JWTLab backend: {exc}")
        raise SystemExit(1)


# ─── jwtlab analyze ───────────────────────────────────────────────────────────

@app.command("analyze")
def analyze(
    token: str = typer.Argument(..., help="Base64url-encoded JWT string"),
    format: str = typer.Option("json", "--format", help="Output format: json (default) or human"),
) -> None:
    """Decode a JWT and print structured analysis. Works fully offline."""
    from jwtlab.analyzer import analyze_token, AnalysisError

    if format not in ("json", "human"):
        err_console.print(f"ERROR: --format must be 'json' or 'human', got '{format}'.")
        raise SystemExit(1)

    try:
        result = analyze_token(token)
    except AnalysisError as exc:
        err_console.print(f"ERROR: {exc}")
        raise SystemExit(1)

    if format == "json":
        print(json.dumps(result, indent=2, default=str))
    else:
        _print_human(result)


def _print_human(result: dict) -> None:
    """Print a Rich-formatted human-readable analysis."""
    from rich.table import Table

    table = Table(title="JWT Analysis", show_lines=True)
    table.add_column("Field", style="bold cyan")
    table.add_column("Value", style="white")

    alg = result.get("algorithm", "?")
    expired = result.get("expired", False)
    sig = result.get("signaturePresent", False)
    dangerous = result.get("dangerousFields", [])

    table.add_row("Algorithm", alg)
    table.add_row("Signature Present", "Yes" if sig else "No")
    table.add_row("Expired", "[bold red][EXPIRED][/bold red]" if expired else "No")

    header = result.get("header", {})
    for k, v in header.items():
        prefix = "[bold yellow][WATCH][/bold yellow] " if k in dangerous else ""
        table.add_row(f"header.{k}", f"{prefix}{v}")

    payload = result.get("payload", {})
    for k, v in payload.items():
        table.add_row(f"payload.{k}", str(v))

    console.print(table)


# ─── jwtlab crack ─────────────────────────────────────────────────────────────

@app.command("crack")
def crack(
    token: str = typer.Argument(..., help="HS256/HS384/HS512 JWT to crack"),
    wordlist: Optional[str] = typer.Option(None, "--wordlist", help="Path to newline-separated wordlist"),
    server: str = typer.Option("http://127.0.0.1:8765", "--server", help="Base URL of running jwtlab server"),
) -> None:
    """Crack an HS* JWT secret by sending it to the running server."""
    import httpx
    from rich.progress import Progress, SpinnerColumn, TextColumn

    # Build wordlist
    if wordlist:
        try:
            words = [w.strip() for w in open(wordlist).readlines() if w.strip()]
        except OSError as exc:
            err_console.print(f"ERROR: could not read wordlist '{wordlist}': {exc}")
            raise SystemExit(1)
        # Truncate to 10,000 entries per spec (built-in default is never subject to this limit)
        if len(words) > 10_000:
            console.print("WARNING: wordlist truncated to 10,000 entries")
            words = words[:10_000]
    else:
        # Built-in 50-word default wordlist; 'secret' is at position ≥ 10
        words = [
            "password", "admin", "123456", "letmein", "qwerty", "dragon",
            "monkey", "welcome", "shadow", "master", "secret", "abc123",
            "football", "superman", "iloveyou", "trustno1", "sunshine",
            "princess", "baseball", "mustang", "access", "696969", "batman",
            "passw0rd", "michael", "000000", "login", "hello", "charlie",
            "donald", "password1", "1234", "cheese", "nintendo", "samsung",
            "hunter", "freedom", "computer", "corvette", "cookie", "joshua",
            "ashley", "jessica", "123abc", "test", "root", "toor", "guest",
            "changeme", "qazwsx",
        ]

    # Quick sanity check on algorithm
    try:
        import base64
        header_b64 = token.split(".")[0]
        header_b64 += "=" * (4 - len(header_b64) % 4)
        header_json = base64.urlsafe_b64decode(header_b64).decode()
        alg = json.loads(header_json).get("alg", "")
        if not alg.startswith("HS"):
            err_console.print(
                f"ERROR: algorithm '{alg}' is not an HMAC algorithm. "
                "jwtlab crack only supports HS256/HS384/HS512."
            )
            raise SystemExit(2)
    except (IndexError, Exception):
        pass  # let the server handle malformed tokens

    url = f"{server.rstrip('/')}/api/v1/crack"
    payload = {"token": token, "wordlist": words}

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
    ) as progress:
        progress.add_task("Cracking token via server...", total=None)
        try:
            response = httpx.post(url, json=payload, timeout=60.0)
        except httpx.ConnectError:
            err_console.print(
                f"ERROR: server unreachable at {server}. "
                "Start the server with: jwtlab serve"
            )
            raise SystemExit(2)
        except httpx.HTTPError as exc:
            err_console.print(f"ERROR: HTTP error while contacting server: {exc}")
            raise SystemExit(2)

    if response.status_code != 200:
        err_console.print(f"ERROR: server returned HTTP {response.status_code}: {response.text}")
        raise SystemExit(2)

    data = response.json()
    attempts = data.get("attempts", 0)
    elapsed = data.get("elapsed_ms", 0)

    if data.get("found"):
        secret = data.get("secret", "")
        console.print(f"[bold green]Found: {secret}[/bold green] ({attempts} attempts, {elapsed}ms)")
        raise SystemExit(0)
    else:
        console.print(f"[bold red]Not found after {attempts} attempts.[/bold red]")
        raise SystemExit(1)


if __name__ == "__main__":
    app()
