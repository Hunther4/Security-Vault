# 🛡️ Security Vault CLI & API

Sistema de gestión de archivos con encriptación de grado militar desarrollado en Python. Este proyecto permite asegurar documentos mediante algoritmos criptográficos modernos, ofreciendo una arquitectura escalable lista para integrarse como un servicio backend (API) o mediante una interfaz de línea de comandos (CLI) robusta.

## ⚠️ Estado del Proyecto

> **Versión 1.1.0** — Después de la auditoría de seguridad, todos los issues CRITICAL fueron resueltos.

## 🚀 Características Principales

* **Cifrado Autenticado (AES-256-GCM):** No solo garantizamos confidencialidad, sino también la **integridad** del archivo; el sistema detecta si el archivo fue modificado tras ser encriptado.
* **Arquitectura Escalable:** Implementación del **Patrón Repositorio (Repository Pattern)**, permitiendo desacoplar la lógica de negocio de la persistencia de datos.
* **Backend API Ready:** Diseñado con **FastAPI** para soportar operaciones remotas de subida y descarga de forma asíncrona.
* **Eficiencia en Memoria:** Procesamiento mediante *streaming* de fragmentos (chunks) de 64KB para manejar archivos grandes sin saturar la RAM.
* **Key Rotation Automática:** Rotación de claves cada 7 días para mantener seguridad a largo plazo.
* **API Key Authentication:** Todas las operaciones requieren autenticación via `X-API-Key`.

## 🏗️ Arquitectura del Sistema

```
1. VALIDACIÓN    → Magic bytes detection (evita archivos maliciosos)
2. STREAMING     → Chunks de 64KB (archivos gigabyte sin RAM overflow)
3. CIFRADO       → AES-256-GCM (nonce único por encriptación)
4. PERSISTENCIA  → SQLite metadatos + binario encriptado
5. AUDITORÍA     → Log de todas las operaciones
```

## 🛡️ Seguridad

| Feature | Implementación |
|---------|----------------|
| Cifrado | AES-256-GCM (cryptography hazmat) |
| Auth | API Key via `X-API-Key` header |
| Key Rotation | Automática cada 7 días |
| Validación | UUID validation, filename sanitization, max size 50MB |
| Permisos | master.key con permisos 0o600 |

## 🛠️ Tecnologías

* **Python 3.x**
* **Criptografía:** `cryptography` (hazmat)
* **API:** `FastAPI`
* **Base de Datos:** `SQLite` + `SQLAlchemy`
* **CLI:** `rich`

## 📋 Instalación

```bash
# Clonar el repositorio
git clone https://github.com/Hunther4/Security-Vault.git
cd Security-Vault

# Crear y activar entorno virtual
python3 -m venv venv
source venv/bin/activate  # Linux/Mac
# venv\Scripts\activate   # Windows

# Instalar dependencias
pip install -r requirements.txt
```

## 🚀 Cómo Usar

### CLI (Línea de comandos)
```bash
python3 main.py
```

### API Server (Servidor)
```bash
# Iniciar el servidor
uvicorn api:app --host 0.0.0.0 --port 8000

# Generar una API Key
python3 -c "from main import generate_api_key; print(generate_api_key())"
```

### Endpoints disponibles

| Método | Endpoint | Descripción |
|--------|----------|-------------|
| POST | `/upload` | Subir archivo encriptado |
| GET | `/download/{document_id}` | Descargar archivo desencriptado |
| GET | `/list` | Listar todos los documentos |

**Headers requeridos para todos los endpoints:**
```
X-API-Key: TU_API_KEY_AQUI
```

## 📁 Estructura del Proyecto

```
Security-Vault/
├── api.py              # Endpoints de FastAPI
├── main.py             # Punto de entrada CLI
├── services.py         # Lógica de negocio
├── repositories.py     # Acceso a datos + encriptación
├── models.py           # Modelos de SQLAlchemy
├── requirements.txt    # Dependencias del proyecto
└── portfolio_test.py   # Tests unitarios
```

## 📝 Changelog (Historial de cambios)

### v1.1.0 (20/04/2026)
- ✅ Añadido autenticación con API Key
- ✅ Rotación de claves cada 7 días
- ✅ Corregido file handle leaks
- ✅ Corregido path traversal vulnerability
- ✅ Añadido input validation (UUID, filename, tamaño)
- ✅ Dependencias con versiones fijadas
- ✅ Mejorado logging
- ✅ Añadido test de encrypt/decrypt

### v1.0.0 (15/03/2025)
- ✅ Versión inicial
- ✅ Encriptación AES-256-GCM
- ✅ Integración con FastAPI
- ✅ Interfaz CLI

## ⚖️ Licencia

MIT License

## 👤 Autor

**Drack** (anteriormente Kimetsu)