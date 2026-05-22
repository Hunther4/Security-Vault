<h1 align="center">🔐 Security Vault</h1>

<p align="center">
  <em>AES-256-GCM encrypted document management system</em>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.12-blue?logo=python" alt="Python">
  <img src="https://img.shields.io/badge/go-1.26-blue?logo=go" alt="Go">
  <img src="https://img.shields.io/badge/license-MIT-green" alt="License">
  <img src="https://img.shields.io/badge/encryption-AES--256--GCM-brightgreen" alt="AES-256-GCM">
</p>

---

## ✨ Features

- **AES-256-GCM** chunked encryption (64KB) with unique nonce per chunk
- **Dual interface**: Python CLI (Rich TUI) + Go CLI (cobra) + FastAPI REST API
- **Key rotation** with full version history — old documents stay decryptable
- **Audit logging** — every encrypt/decrypt/rotate is logged
- **Streaming** — handles files up to 50MB without loading into RAM
- **API key authentication** via `X-API-Key` header
- **Path traversal prevention**, magic byte detection, filename sanitization

## 📦 Stack

| Layer | Technology |
|-------|-----------|
| **CLI (legacy)** | Python + Rich |
| **CLI (new)** | Go + cobra + viper |
| **API** | FastAPI + uvicorn |
| **Crypto** | AES-256-GCM (`cryptography` / stdlib `crypto/aes`) |
| **Database** | SQLite + SQLAlchemy |
| **Auth** | X-API-Key header |

## 🏗 Architecture

```
┌──────────┐   ┌──────────┐   ┌───────────┐
│ Go CLI   │   │ Python   │   │ External  │
│ (cobra)  │   │ CLI(Rich)│   │ HTTP      │
└────┬─────┘   └────┬─────┘   └─────┬─────┘
     │              │              │
     └──────────────┼──────────────┘
                    ▼
            ┌──────────────┐
            │   FastAPI    │
            │   (api.py)   │
            └──────┬───────┘
                   │
         ┌─────────┼─────────┐
         │         │         │
    ┌────▼───┐ ┌──▼───┐ ┌───▼────┐
    │Vault   │ │Local │ │SQLite  │
    │Service │ │Store │ │+ Audit │
    └────────┘ └──────┘ └────────┘
```

## 🚀 Quick Start

### Python API + CLI

```bash
git clone https://github.com/Hunther4/Security-Vault.git
cd Security-Vault
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

# Start the API
./venv/bin/uvicorn api:app --port 8000

# Or use the Python CLI directly
./venv/bin/python main.py
```

### Go CLI

```bash
go build -o bin/vault ./cmd/vault
./bin/vault --help
```

## 📟 Go CLI Commands

| Command | Description |
|---------|-------------|
| `vault encrypt <file>` | Encrypt and upload |
| `vault decrypt <id>` | Download and decrypt |
| `vault list` | List documents |
| `vault rotate` | Rotate master key |
| `vault serve` | Start API server |
| `vault config init` | Create config file |
| `vault config show` | Show config |

All commands support `--json` for scripting and `--api-key` / `--api-url` flags.

### JSON output example

```bash
vault list --json --api-key "mykey" --api-url "http://localhost:8000"
```

## 🐳 Docker

```bash
docker-compose up -d
# API running on http://localhost:8000
```

## 🔐 API Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/upload` | X-API-Key | Upload & encrypt a file |
| `GET` | `/download/{id}` | X-API-Key | Download & decrypt |
| `GET` | `/list` | X-API-Key | List all documents |
| `POST` | `/rotate` | X-API-Key | Rotate master key |

### Upload example

```bash
curl -X POST http://localhost:8000/upload \
  -H "X-API-Key: mykey" \
  -F "file=@document.pdf"
```

## 🔑 Key Management

Keys are stored in SQLite with version history:

- **Auto-create** on first run (both API and CLI)
- **Rotation** via `POST /rotate` or `vault rotate`
- **Per-document tracking** — each document stores which key version encrypted it
- **Old keys preserved** — decrypt always works

## 🧪 Tests

```bash
# Python
python -m pytest portfolio_test.py -v

# Go
go test ./... -v
```

## 📦 Release (GoReleaser)

```bash
make release
```

Builds for linux/darwin/windows, amd64/arm64.

## 📄 License

MIT — see [LICENSE](./LICENSE).
