import os
import re
import uuid
import logging
import time
from contextlib import asynccontextmanager
from fastapi import FastAPI, UploadFile, File, HTTPException, Depends, Header, Request, BackgroundTasks
from fastapi.responses import StreamingResponse, JSONResponse
from datetime import datetime
from typing import BinaryIO, Optional
from dotenv import load_dotenv
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from pythonjsonlogger import jsonlogger

load_dotenv()

from models import Document, Base
from services import VaultService
from repositories import AES256GCMChunkedProvider, LocalStorageRepository, SQLiteRepository, KeyRepository, SecurityValidator, KeyNotFoundError
from sqlalchemy import create_engine, text as sa_text

# ── JSON Logging ────────────────────────────────────────────────────────
log_handler = logging.StreamHandler()
log_handler.setFormatter(jsonlogger.JsonFormatter(
    fmt="%(asctime)s %(name)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S%z",
))
logger = logging.getLogger(__name__)
logger.addHandler(log_handler)
logger.handlers = [log_handler]
logger.setLevel(logging.INFO)

# Silence noisy libs
logging.getLogger("uvicorn.access").handlers = []
logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)

# ── App Setup ───────────────────────────────────────────────────────────
DB_PATH = os.path.join(os.path.dirname(__file__), "vault.db")
STORAGE_PATH = "./secure_storage"

vault_api_keys = os.environ.get("VAULT_API_KEYS")
if not vault_api_keys:
    raise RuntimeError("VAULT_API_KEYS environment variable is not set")
API_KEYS = set(vault_api_keys.split(","))

MAX_UPLOAD_SIZE = 50 * 1024 * 1024

# ── Rate Limiter ────────────────────────────────────────────────────────
limiter = Limiter(key_func=get_remote_address)

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("vault.api.startup", extra={"event": "startup"})
    yield
    logger.info("vault.api.shutdown", extra={"event": "shutdown"})

app = FastAPI(title="Secure Vault API", lifespan=lifespan)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ── Database Engine (WAL mode) ─────────────────────────────────────────
_db_engine = create_engine(f"sqlite:///{DB_PATH}", echo=False, connect_args={"check_same_thread": False})
with _db_engine.connect() as conn:
    conn.execute(sa_text("PRAGMA journal_mode=WAL"))
    conn.execute(sa_text("PRAGMA busy_timeout=5000"))
    conn.execute(sa_text("PRAGMA synchronous=NORMAL"))
    conn.commit()

def validate_uuid(document_id: str) -> str:
    """Validate that document_id is a valid UUID format."""
    try:
        uuid.UUID(document_id)
        return document_id
    except ValueError:
        raise HTTPException(
            status_code=400, 
            detail="Invalid document_id format. Must be a valid UUID."
        )

def validate_actor(actor: str) -> str:
    """Validate and sanitize the actor parameter."""
    if not actor or not actor.strip():
        raise HTTPException(status_code=400, detail="Actor parameter is required")
    # Sanitize: only allow alphanumeric, underscore, hyphen, and limited punctuation
    sanitized = re.sub(r'[^a-zA-Z0-9_-]', '_', actor.strip())
    if len(sanitized) > 64:
        sanitized = sanitized[:64]
    return sanitized

def validate_filename(filename: str) -> str:
    """Validate and sanitize filename to only allow safe characters."""
    if not filename or not filename.strip():
        raise HTTPException(status_code=400, detail="Filename cannot be empty")
    
    # Use the SecurityValidator to sanitize the filename
    try:
        safe_filename = SecurityValidator.sanitize_filename(filename)
        return safe_filename
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

def validate_file_size(file: UploadFile) -> int:
    """Validate file size does not exceed maximum allowed size."""
    size = 0
    chunk_size = 1024 * 1024  # 1 MB chunks
    
    while True:
        chunk = file.file.read(chunk_size)
        if not chunk:
            break
        size += len(chunk)
        if size > MAX_UPLOAD_SIZE:
            raise HTTPException(
                status_code=413,
                detail=f"File size exceeds maximum allowed size of {MAX_UPLOAD_SIZE // (1024*1024)} MB"
            )
    
    # Reset file position
    file.file.seek(0)
    return size

def verify_api_key(x_api_key: Optional[str] = Header(None)) -> str:
    """Verify the API key from the X-API-Key header."""
    if not x_api_key:
        raise HTTPException(status_code=401, detail="Missing X-API-Key header")
    if x_api_key not in API_KEYS:
        raise HTTPException(status_code=403, detail="Invalid API key")
    return x_api_key

def get_key_repo():
    return KeyRepository(db_url=f"sqlite:///{DB_PATH}", engine=_db_engine)

def get_vault_service(key_repo: KeyRepository = Depends(get_key_repo)):
    try:
        active_key = key_repo.get_active_key()
    except KeyNotFoundError:
        master_key = os.urandom(32).hex()
        key_repo.create_key_version(master_key)
        active_key = key_repo.get_active_key()
        logger.info("Auto-initialized master key")

    crypto = AES256GCMChunkedProvider(key_hex=active_key.master_key_hex)
    storage = LocalStorageRepository(base_path=STORAGE_PATH)
    sql_db = SQLiteRepository(db_url=f"sqlite:///{DB_PATH}", engine=_db_engine)
    
    return VaultService(crypto=crypto, storage=storage, sql_db=sql_db, key_repo=key_repo)

@app.post("/upload")
@limiter.limit("20/minute")
def upload_document(
    request: Request,
    file: UploadFile = File(...),
    actor: str = "default_user",
    x_api_key: str = Depends(verify_api_key),
    service: VaultService = Depends(get_vault_service)
):
    try:
        # Validate file size before processing
        file_size = validate_file_size(file)
        logger.info(f"Upload request - filename: {file.filename}, size: {file_size} bytes, actor: {actor}")
        
        safe_actor = validate_actor(actor)
        
        # Validate and sanitize filename
        safe_filename = validate_filename(file.filename)
        
        doc, _ = service.upload_secure_document(safe_filename, file.file, actor=safe_actor)
        logger.info(f"Upload successful - document_id: {doc.id}")
        return {"document_id": doc.id, "filename": doc.original_filename}
    except HTTPException:
        raise
    except ValueError as e:
        logger.warning(f"Validation error during upload: {str(e)}")
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Upload failed: {type(e).__name__}: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error during upload")

@app.get("/download/{document_id}")
@limiter.limit("30/minute")
def download_document(
    request: Request,
    document_id: str,
    background_tasks: BackgroundTasks,
    actor: str = "default_user",
    x_api_key: str = Depends(verify_api_key),
    service: VaultService = Depends(get_vault_service)
):
    try:
        # Validate document_id is a valid UUID before querying
        valid_document_id = validate_uuid(document_id)
        logger.info(f"Download request - document_id: {valid_document_id}, actor: {actor}")
        
        safe_actor = validate_actor(actor)
        filename, decrypted_stream = service.download_secure_document(valid_document_id, actor=safe_actor)
        
        logger.info(f"Download successful - document_id: {valid_document_id}, filename: {filename}")
        
        # Close the stream after the response is sent
        background_tasks.add_task(decrypted_stream.close)
        
        return StreamingResponse(
            decrypted_stream,
            media_type="application/octet-stream",
            headers={"Content-Disposition": f"attachment; filename={filename}"},
        )
    except HTTPException:
        raise
    except ValueError as e:
        logger.warning(f"Validation error during download: {str(e)}")
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Download failed: {type(e).__name__}: {str(e)}")
        raise HTTPException(status_code=404, detail="Document not found or decryption failed")

@app.get("/list")
@limiter.limit("30/minute")
def list_documents(
    request: Request,
    x_api_key: str = Depends(verify_api_key),
    service: VaultService = Depends(get_vault_service)
):
    try:
        docs = service.list_documents()
        return {"documents": docs}
    except Exception as e:
        logger.error("list_failed", extra={"error": str(e)})
        raise HTTPException(status_code=500, detail="Failed to list documents")

@app.post("/rotate")
@limiter.limit("10/minute")
def rotate_keys(
    request: Request,
    x_api_key: str = Depends(verify_api_key),
    service: VaultService = Depends(get_vault_service)
):
    try:
        result = service.rotate_key_manually()
        return result
    except Exception as e:
        logger.error("rotate_failed", extra={"error": str(e)})
        raise HTTPException(status_code=500, detail="Key rotation failed")

# ── Healthcheck ──────────────────────────────────────────────────────────
@app.get("/health")
def healthcheck():
    status = {"status": "ok", "version": "1.2.0"}
    try:
        with _db_engine.connect() as conn:
            conn.execute(sa_text("SELECT 1"))
        status["database"] = "connected"
    except Exception as e:
        status["status"] = "degraded"
        status["database"] = f"error: {e}"

    storage_ok = os.path.isdir(STORAGE_PATH) and os.access(STORAGE_PATH, os.R_OK | os.W_OK)
    status["storage"] = "ok" if storage_ok else "unavailable"

    try:
        kr = KeyRepository(db_url=f"sqlite:///{DB_PATH}", engine=_db_engine)
        kr.get_active_key()
        status["crypto"] = "ok"
    except Exception as e:
        status["crypto"] = f"error: {e}"
        if status["status"] == "ok":
            status["status"] = "degraded"

    status_code = 200 if status["status"] == "ok" else 503
    return JSONResponse(content=status, status_code=status_code)
