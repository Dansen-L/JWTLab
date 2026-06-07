#!/usr/bin/env bash
# JWTLab — Development Environment Setup & Launch Script
# Usage: bash init.sh [--dev] [--port PORT] [--host HOST]
# --dev   : starts the Vite dev server alongside the FastAPI backend (hot-reload)
# --port  : FastAPI port (default 8765)
# --host  : FastAPI bind host (default 127.0.0.1)
set -euo pipefail

# ─── Colour helpers ───────────────────────────────────────────────────────────
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
info()    { echo -e "${GREEN}[init.sh]${NC} $*"; }
warn()    { echo -e "${YELLOW}[init.sh]${NC} $*"; }
error()   { echo -e "${RED}[init.sh] ERROR:${NC} $*" >&2; }

# ─── Argument parsing ─────────────────────────────────────────────────────────
DEV_MODE=false
PORT=8765
HOST="127.0.0.1"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dev)    DEV_MODE=true; shift ;;
    --port)   PORT="$2";    shift 2 ;;
    --host)   HOST="$2";    shift 2 ;;
    *) error "Unknown argument: $1"; exit 1 ;;
  esac
done

# ─── Python version check ─────────────────────────────────────────────────────
info "Checking Python version..."
if ! command -v python3 &>/dev/null; then
  error "python3 not found. Please install Python 3.11+."
  exit 1
fi

PY_VER=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
PY_MAJOR=$(echo "$PY_VER" | cut -d. -f1)
PY_MINOR=$(echo "$PY_VER" | cut -d. -f2)

if [[ "$PY_MAJOR" -lt 3 ]] || [[ "$PY_MAJOR" -eq 3 && "$PY_MINOR" -lt 11 ]]; then
  error "Python 3.11+ is required; found Python ${PY_VER}."
  exit 1
fi
info "Python ${PY_VER} ✓"

# ─── Virtual environment ──────────────────────────────────────────────────────
VENV_DIR=".venv"
if [[ ! -d "$VENV_DIR" ]]; then
  info "Creating virtual environment in ${VENV_DIR}/ ..."
  python3 -m venv "$VENV_DIR"
fi

# Activate venv
# shellcheck disable=SC1091
source "${VENV_DIR}/bin/activate"
info "Virtual environment activated."

# ─── Install Python dependencies ──────────────────────────────────────────────
info "Installing Python package in editable mode (pip install -e .[dev])..."
if [[ -f "pyproject.toml" ]]; then
  pip install --quiet -e ".[dev]" 2>&1 || pip install --quiet -e . 2>&1
  info "Python dependencies installed ✓"
else
  warn "pyproject.toml not found yet — skipping pip install (run again after scaffold is created)."
fi

# ─── Node.js / frontend (dev mode only) ──────────────────────────────────────
if [[ "$DEV_MODE" == true ]]; then
  if ! command -v node &>/dev/null; then
    error "Node.js not found. Install Node 18+ for dev mode (frontend hot-reload)."
    error "End-users can skip this — they use 'jwtlab serve' with pre-built assets."
    exit 1
  fi

  NODE_VER=$(node -e "process.stdout.write(process.versions.node)")
  NODE_MAJOR=$(echo "$NODE_VER" | cut -d. -f1)
  if [[ "$NODE_MAJOR" -lt 18 ]]; then
    error "Node 18+ required; found Node ${NODE_VER}."
    exit 1
  fi
  info "Node ${NODE_VER} ✓"

  if [[ -d "frontend" ]]; then
    info "Installing frontend Node dependencies..."
    (cd frontend && npm install --silent)
    info "Frontend npm install ✓"
  else
    warn "frontend/ directory not found yet — npm install skipped."
  fi
fi

# ─── Launch ───────────────────────────────────────────────────────────────────
if [[ "$DEV_MODE" == true ]]; then
  # Development mode: run FastAPI backend + Vite dev server concurrently
  info "Starting development mode:"
  info "  • FastAPI backend → http://${HOST}:${PORT}"
  info "  • Vite dev server  → http://localhost:5173 (with HMR)"
  echo ""
  warn "Press Ctrl+C to stop both servers."
  echo ""

  # Launch Vite in the background
  if [[ -d "frontend" ]]; then
    (cd frontend && npm run dev) &
    VITE_PID=$!
    info "Vite dev server started (PID ${VITE_PID})."
  fi

  # Launch FastAPI backend (uvicorn via jwtlab CLI)
  if command -v jwtlab &>/dev/null; then
    jwtlab serve --port "$PORT" --host "$HOST"
  else
    # Fallback: run uvicorn directly
    uvicorn jwtlab.server:app --host "$HOST" --port "$PORT" --reload
  fi

  # Cleanup on exit
  if [[ -n "${VITE_PID:-}" ]]; then
    kill "$VITE_PID" 2>/dev/null || true
  fi

else
  # Production/end-user mode: serve pre-built frontend + FastAPI from one port
  info "Starting JWTLab (production mode)..."
  info "  • URL  → http://${HOST}:${PORT}"
  info "  • API  → http://${HOST}:${PORT}/api/v1"
  info ""
  info "Health check: curl http://${HOST}:${PORT}/api/v1/health"
  echo ""
  warn "Press Ctrl+C to stop the server."
  echo ""

  if command -v jwtlab &>/dev/null; then
    jwtlab serve --port "$PORT" --host "$HOST"
  else
    error "jwtlab CLI not found. Run: pip install -e ."
    error "Then re-run: bash init.sh"
    exit 1
  fi
fi
