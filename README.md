# JWTLab — Interactive JWT Attack Visualizer

An animated, interactive web application (with a companion CLI) that teaches
developers and security learners how JSON Web Token attacks work — from first
principles through hands-on exploitation of intentionally vulnerable endpoints.

## Overview

JWTLab pairs narrative explanations with step-by-step animated attack flows
and interactive exercises where learners construct or mutate JWTs and fire them
at an embedded sandbox API. Six canonical attack modules are covered:

| Module | Attack Class | CVE |
|--------|-------------|-----|
| alg=none | Algorithm None Bypass | CVE-2015-9235 |
| alg-confusion | RS256 → HS256 Algorithm Confusion | CVE-2016-10555 |
| weak-secret | Weak HMAC Secret Brute-force | — |
| kid-sqli | Key ID SQL Injection | — |
| jku-injection | JKU / JWK Header Injection | — |
| exp-bypass | Expired Token Extension (exp bypass) | — |

## Quick Start (End Users)

No Docker, no API keys, no Node.js required.

```bash
pip install .
jwtlab serve --port 8765
# Open http://localhost:8765 in your browser
```

## Development Setup

Requires Python 3.11+ and Node 18+ (for frontend hot-reload only).

```bash
# Clone and enter the project
git clone <repo-url>
cd jwt-playground

# Option 1 — Automated setup + production server
bash init.sh

# Option 2 — Dev mode (hot-reload frontend + FastAPI backend)
bash init.sh --dev

# Option 3 — Manual setup
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
cd frontend && npm install && npm run build && cd ..
jwtlab serve --port 8765
```

## CLI Commands

```bash
# Start the server
jwtlab serve [--port PORT] [--host HOST]

# Analyze a JWT token (offline, no server needed)
jwtlab analyze <TOKEN> [--format json|human]

# Crack a JWT's HMAC secret (requires server running)
jwtlab crack <TOKEN> [--wordlist PATH] [--server URL]
```

## Technology Stack

- **Frontend**: React 18 + Vite, Framer Motion, Tailwind CSS, React Router
- **Fonts**: Space Grotesk, DM Sans, JetBrains Mono (bundled via @fontsource — no CDN)
- **Backend**: FastAPI (Python 3.11+), PyJWT, python-jose, uvicorn
- **CLI**: Typer + Rich
- **Packaging**: pyproject.toml; frontend pre-built into the Python wheel

## Architecture

All state is ephemeral (in-process memory or browser localStorage). No disk
database, no persistent files, no external connections. The kid-sqli module
uses an in-memory SQLite (`:memory:`) database.

Toggle-patch state is server-wide and resets on server restart. All modules
start in vulnerable mode (`vulnerabilityActive = true`) on each launch.

## Security Notice

JWTLab exposes **intentionally vulnerable endpoints** for educational purposes.
Run only on `127.0.0.1` (the default). Using `--host 0.0.0.0` on a shared
network is unsafe and will display a warning banner.

## API Reference

All paths include the `/api/v1` prefix.

| Method | Path | Description |
|--------|------|-------------|
| GET | /api/v1/health | Server health check |
| GET | /api/v1/modules | List all modules and patch state |
| POST | /api/v1/analyze | Decode and analyze a JWT |
| POST | /api/v1/crack | Brute-force an HS* JWT secret |
| POST | /api/v1/attack/{module}/login | Issue a module JWT |
| POST | /api/v1/attack/{module}/verify | Verify against the module's endpoint |
| POST | /api/v1/attack/{module}/toggle-patch | Toggle vulnerable/patched mode |
| GET | /api/v1/attack/alg-confusion/public-key | RSA public key PEM |
| GET | /api/v1/attack/jku-injection/attacker-jwks | Attacker JWK Set |
| GET | /api/v1/attack/jku-injection/attacker-private-key | Attacker private key + JWKS URL |

## Project Structure

```
jwt-playground/
├── pyproject.toml          # Python package + build config
├── init.sh                 # Dev environment setup script
├── feature_list.json       # Test case registry (source of truth)
├── frontend/               # React 18 + Vite application
│   ├── src/
│   │   ├── components/     # Shared UI components
│   │   ├── modules/        # Per-attack-module pages
│   │   ├── pages/          # App shell pages
│   │   └── main.tsx        # Entry point
│   ├── public/
│   ├── index.html
│   ├── vite.config.ts
│   ├── tailwind.config.js
│   └── package.json
├── jwtlab/                 # Python package
│   ├── __init__.py
│   ├── cli.py              # Typer CLI (serve, analyze, crack)
│   ├── server.py           # FastAPI app
│   ├── attacks/            # Per-module vulnerable endpoint logic
│   │   ├── alg_none.py
│   │   ├── alg_confusion.py
│   │   ├── weak_secret.py
│   │   ├── kid_sqli.py
│   │   ├── jku_injection.py
│   │   └── exp_bypass.py
│   └── static/             # Bundled frontend assets (from npm run build)
└── README.md
```
