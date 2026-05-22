import os
import re
import uuid
import threading
import logging
import shutil
from typing import BinaryIO, Protocol, Iterator, Tuple, Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy import create_engine, text, MetaData
from sqlalchemy.orm import sessionmaker
from models import Base, Document, KeyVersion, DocumentModel, AuditLogModel, KeyVersionModel
from datetime import datetime
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Configure module-level logging
logger = logging.getLogger(__name__)

class VaultError(Exception):
    pass

class DocumentNotFoundError(VaultError):
    pass

class InvalidUUIDError(VaultError):
    pass

class KeyNotFoundError(VaultError):
    pass

class ICryptoProvider(Protocol):
    def encrypt_stream(self, header_bytes: bytes, remaining_stream: BinaryIO, output_stream: BinaryIO, max_size: int) -> int: ...
    def decrypt_stream(self, input_stream: BinaryIO, output_stream: BinaryIO) -> None: ...

class IStorageRepository(Protocol):
    def save_encrypted_stream(self, doc_id: uuid.UUID, stream: BinaryIO) -> str: ...
    def get_encrypted_stream(self, storage_path: str) -> BinaryIO: ...

class ISQLRepository(Protocol):
    def save_metadata(self, doc: Document, storage_path: str, key_id: str = None) -> None: ...
    def log_audit(self, doc_id: uuid.UUID, action: str, actor: str, key_id: str = None) -> None: ...
    def get_metadata(self, doc_id: str) -> Tuple[str, str, str]: ...
    def list_all(self) -> list[dict]: ...

class IKeyRepository(Protocol):
    def get_active_key(self) -> KeyVersion: ...
    def create_key_version(self, master_key_hex: str) -> KeyVersion: ...
    def rotate_key(self, new_master_key_hex: str) -> KeyVersion: ...
    def get_key_by_id(self, key_id: str) -> KeyVersion: ...
    def get_keys_before_date(self, date: datetime) -> list[KeyVersion]: ...

class SecurityValidator:
    MAGIC_SIGNATURES = {
        b'%PDF-': 'application/pdf',
        b'\x89PNG\r\n\x1a\n': 'image/png',
        b'\xff\xd8\xff': 'image/jpeg',
        b'Este es': 'text/plain'
    }

    @staticmethod
    def sanitize_filename(filename: str) -> str:
        """Sanitize filename to prevent path traversal and other attacks."""
        if not filename or not filename.strip():
            raise ValueError("El nombre del archivo no puede estar vacío.")
        
        # Get basename only - strip any directory components
        base_name = os.path.basename(filename)
        
        # Check for path traversal attempts (..)
        if ".." in filename:
            raise ValueError("Path traversal attempt detected.")
        
        # Check for absolute paths (不应该有)
        if os.path.isabs(filename):
            raise ValueError("Absolute paths are not allowed.")
        
        # Check for symlinks in the path (resolve and validate)
        if os.path.islink(filename):
            raise ValueError("Symlinks are not allowed.")
        
        # Validate UUIDs in filename if present
        uuid_pattern = r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'
        uuids_found = re.findall(uuid_pattern, filename)
        for found_uuid in uuids_found:
            try:
                uuid.UUID(found_uuid)
            except ValueError:
                raise InvalidUUIDError(f"UUID inválido encontrado en nombre de archivo: {found_uuid}")
        
        # Final sanitization - only allow safe characters
        safe_name = re.sub(r'[^a-zA-Z0-9_.-]', '_', base_name)
        
        # Prevent empty or None after sanitization
        if not safe_name or safe_name.startswith('.'):
            safe_name = f'untrusted_file_{safe_name}'
        
        return safe_name

    @staticmethod
    def validate_magic_bytes(header_bytes: bytes) -> str:
        # 1. Firmas conocidas
        for sig, mime in SecurityValidator.MAGIC_SIGNATURES.items():
            if header_bytes.startswith(sig):
                return mime
        
        # 2. Si no es firma conocida, intentar validar si es texto plano
        try:
            header_bytes.decode('utf-8')
            return 'text/plain'
        except UnicodeDecodeError:
            pass
            
        # 3. Binario desconocido — lo aceptamos como application/octet-stream
        #    El vault encripta cualquier contenido, la validación de tipo es
        #    responsabilidad de la capa de aplicación, no del core de encriptación
        return 'application/octet-stream'

class AES256GCMChunkedProvider(ICryptoProvider):
    CHUNK_SIZE = 64 * 1024
    def __init__(self, key_hex: str):
        self.key = bytes.fromhex(key_hex)
        if len(self.key) != 32:
            raise ValueError("Llave inválida. Debe ser 256-bit.")

    def encrypt_stream(self, header_bytes: bytes, remaining_stream: BinaryIO, output_stream: BinaryIO, max_size: int) -> int:
        # Write version byte (v1)
        output_stream.write(b'\x01')
        
        total_bytes = 0
        aesgcm = AESGCM(self.key)
        def chunk_generator() -> Iterator[bytes]:
            yield header_bytes
            while True:
                chunk = remaining_stream.read(self.CHUNK_SIZE)
                if not chunk: break
                yield chunk
        for idx, chunk in enumerate(chunk_generator()):
            total_bytes += len(chunk)
            if total_bytes > max_size:
                raise BufferError(f"Excede límite de {max_size} bytes.")
            # Sequence number as AAD (4 bytes, big endian)
            aad = idx.to_bytes(4, byteorder='big')
            nonce = os.urandom(12)
            ciphertext = aesgcm.encrypt(nonce, chunk, aad)
            output_stream.write(len(ciphertext).to_bytes(4, byteorder='big'))
            output_stream.write(nonce)
            output_stream.write(ciphertext)
        return total_bytes
    
    def decrypt_stream(self, input_stream: BinaryIO, output_stream: BinaryIO) -> None:
        # Read version byte
        version_byte = input_stream.read(1)
        if not version_byte: return
        
        version = version_byte[0]
        aesgcm = AESGCM(self.key)
        
        # Handle v0 backward compatibility: if not \x01, it's the first byte of the first chunk length
        if version != 1:
            # Reconstruct the first chunk length
            first_len_bytes = version_byte + input_stream.read(3)
            if len(first_len_bytes) < 4: return
            
            chunk_size = int.from_bytes(first_len_bytes, byteorder='big')
            nonce = input_stream.read(12)
            ciphertext = input_stream.read(chunk_size)
            plaintext_chunk = aesgcm.decrypt(nonce, ciphertext, None)
            output_stream.write(plaintext_chunk)
            
            # Now continue with v0 (no AAD)
            while True:
                chunk_size_bytes = input_stream.read(4)
                if not chunk_size_bytes: break
                chunk_size = int.from_bytes(chunk_size_bytes, byteorder='big')
                nonce = input_stream.read(12)
                ciphertext = input_stream.read(chunk_size)
                plaintext_chunk = aesgcm.decrypt(nonce, ciphertext, None)
                output_stream.write(plaintext_chunk)
            return

        # Version 1: use sequence numbers as AAD
        chunk_idx = 0
        while True:
            chunk_size_bytes = input_stream.read(4)
            if not chunk_size_bytes: break
            chunk_size = int.from_bytes(chunk_size_bytes, byteorder='big')
            nonce = input_stream.read(12)
            ciphertext = input_stream.read(chunk_size)
            aad = chunk_idx.to_bytes(4, byteorder='big')
            plaintext_chunk = aesgcm.decrypt(nonce, ciphertext, aad)
            output_stream.write(plaintext_chunk)
            chunk_idx += 1


class LocalStorageRepository(IStorageRepository):
    _instance_lock = threading.Lock()
    
    def __init__(self, base_path: str):
        with LocalStorageRepository._instance_lock:
            self.base_path = base_path
            real_base = os.path.realpath(base_path)
            # Create and validate the base path exists and is accessible
            try:
                os.makedirs(real_base, exist_ok=True)
                os.chmod(real_base, 0o750)  # Restrict permissions
                logger.info(f"Storage initialized at: {real_base}")
            except OSError as e:
                raise VaultError(f"Failed to create storage directory: {e}")
        self._operation_lock = threading.RLock()
    
    def _validate_storage_path(self, storage_path: str) -> str:
        """Validate and sanitize storage path to prevent path traversal attacks."""
        # Resolve real path to handle symlinks
        real_path = os.path.realpath(storage_path)
        
        # Get the real base path
        real_base = os.path.realpath(self.base_path)
        
        # Check that resolved path is within base path
        if not real_path.startswith(real_base + os.sep) and real_path != real_base:
            raise ValueError(f"Invalid storage path: {storage_path}")
        
        # Ensure path is absolute (storage should always use absolute paths internally)
        if not os.path.isabs(real_path):
            raise ValueError(f"Storage path must be absolute: {storage_path}")
        
        return real_path
    
    def save_encrypted_stream(self, doc_id: uuid.UUID, stream: BinaryIO, key_id: str = None) -> str:
        """Save encrypted stream with context manager to prevent leaks."""
        file_path = os.path.join(self.base_path, f"{doc_id}.enc")
        # Validate path before saving
        file_path = self._validate_storage_path(file_path)
        with open(file_path, "wb") as f:
            shutil.copyfileobj(stream, f)
        return file_path
    
    def get_encrypted_stream(self, storage_path: str) -> BinaryIO:
        """Get encrypted stream with proper file handle management.
        
        Returns a context manager that ensures file is closed after use.
        """
        # Validate path before opening
        validated_path = self._validate_storage_path(storage_path)
        
        if not os.path.exists(validated_path):
            raise FileNotFoundError(f"Archivo encriptado no encontrado: {validated_path}")
        
        # Return a context manager wrapper that handles closing
        class ManagedFileWrapper:
            def __init__(self, path: str):
                self._file = open(path, "rb")
                self._path = path
            
            def __enter__(self):
                return self._file
            
            def __exit__(self, exc_type, exc_val, exc_tb):
                self._file.close()
                return False
            
            def read(self, size: int = -1):
                return self._file.read(size)
        
        return ManagedFileWrapper(validated_path)

class SQLiteRepository(ISQLRepository):
    def __init__(self, db_url: str = "sqlite:///vault.db", engine=None):
        if engine is not None:
            self.engine = engine
        else:
            self.engine = create_engine(db_url, connect_args={"check_same_thread": False})
            with self.engine.connect() as conn:
                conn.execute(text("PRAGMA journal_mode=WAL"))
                conn.execute(text("PRAGMA busy_timeout=5000"))
                conn.execute(text("PRAGMA synchronous=NORMAL"))
                conn.commit()
        Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine)
    
    def save_metadata(self, doc: Document, storage_path: str, key_id: str = None) -> None:
        with self.Session() as session:
            db_doc = DocumentModel(
                id=str(doc.id), 
                original_filename=doc.original_filename, 
                safe_filename=doc.safe_filename, 
                content_type=doc.content_type, 
                size_bytes=doc.size_bytes, 
                storage_path=storage_path, 
                key_id=key_id,
                created_at=doc.created_at
            )
            session.add(db_doc)
            session.commit()
    
    def log_audit(self, doc_id: uuid.UUID, action: str, actor: str, key_id: str = None) -> None:
        with self.Session() as session:
            log = AuditLogModel(
                log_id=str(uuid.uuid4()), 
                document_id=str(doc_id), 
                action=action, 
                actor=actor, 
                key_id=key_id,
                timestamp=datetime.now()
            )
            session.add(log)
            session.commit()
    
    def get_metadata(self, doc_id: str) -> Tuple[str, str, str]:
        with self.Session() as session:
            db_doc = session.query(DocumentModel).filter_by(id=doc_id).first()
            if not db_doc:
                raise DocumentNotFoundError(f"Documento no encontrado con ID: {doc_id}")
            # Return key_id used for encryption (fallback to latest active if not set for old docs)
            key_id = db_doc.key_id if db_doc.key_id else None
            return db_doc.storage_path, db_doc.original_filename, key_id

    def list_all(self) -> list[dict]:
        with self.Session() as session:
            docs = session.query(DocumentModel).order_by(DocumentModel.created_at.desc()).all()
            return [
                {
                    "id": d.id,
                    "original_filename": d.original_filename,
                    "content_type": d.content_type,
                    "size_bytes": d.size_bytes,
                    "created_at": d.created_at.isoformat() if d.created_at else None,
                }
                for d in docs
            ]

class KeyRepository(IKeyRepository):
    def __init__(self, db_url: str = "sqlite:///vault.db", engine=None):
        self.db_url = db_url
        if engine is not None:
            self.engine = engine
        else:
            self.engine = create_engine(db_url, connect_args={"check_same_thread": False})
            with self.engine.connect() as conn:
                conn.execute(text("PRAGMA journal_mode=WAL"))
                conn.execute(text("PRAGMA busy_timeout=5000"))
                conn.execute(text("PRAGMA synchronous=NORMAL"))
                conn.commit()
        Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine)
        
        # KEK for protecting master keys in DB
        self.kek_hex = os.environ.get("VAULT_KEK")
        if not self.kek_hex:
            raise RuntimeError("VAULT_KEK environment variable must be set to encrypt master keys.")
        self.kek = bytes.fromhex(self.kek_hex)
        if len(self.kek) != 32:
            raise ValueError("VAULT_KEK must be a 32-byte hex string (64 characters).")

    def _encrypt_key(self, master_key_hex: str) -> str:
        aesgcm = AESGCM(self.kek)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, master_key_hex.encode(), None)
        return (nonce + ciphertext).hex()

    def _decrypt_key(self, encrypted_key_hex: str) -> str:
        data = bytes.fromhex(encrypted_key_hex)
        nonce = data[:12]
        ciphertext = data[12:]
        aesgcm = AESGCM(self.kek)
        return aesgcm.decrypt(nonce, ciphertext, None).decode()

    def get_active_key(self) -> KeyVersion:
        now = datetime.now()
        with self.Session() as session:
            key_record = session.query(KeyVersionModel).filter(
                KeyVersionModel.is_active == True,
                KeyVersionModel.expires_at > now
            ).order_by(KeyVersionModel.created_at.desc()).first()
            if not key_record:
                raise KeyNotFoundError("No hay clave activa.")
            return KeyVersion(key_record.id, self._decrypt_key(key_record.master_key_hex), key_record.created_at, key_record.expires_at, True)
    def create_key_version(self, master_key_hex: str) -> KeyVersion:
        with self.Session() as session:
            from datetime import timedelta
            expires_at = datetime.now() + timedelta(days=7)
            encrypted_key = self._encrypt_key(master_key_hex)
            key_record = KeyVersionModel(master_key_hex=encrypted_key, expires_at=expires_at, is_active=1)
            session.add(key_record)
            session.commit()
            return KeyVersion(key_record.id, master_key_hex, key_record.created_at, expires_at, True)
    def rotate_key(self, new_master_key_hex: str) -> KeyVersion:
        with self.Session() as session:
            active_key = session.query(KeyVersionModel).filter_by(is_active=1).first()
            if active_key:
                active_key.is_active = 0
            from datetime import timedelta
            expires_at = datetime.now() + timedelta(days=7)
            encrypted_key = self._encrypt_key(new_master_key_hex)
            new_key_record = KeyVersionModel(master_key_hex=encrypted_key, expires_at=expires_at, is_active=1)
            session.add(new_key_record)
            session.commit()
            return KeyVersion(new_key_record.id, new_master_key_hex, new_key_record.created_at, expires_at, True)
    def get_key_by_id(self, key_id: str) -> KeyVersion:
        with self.Session() as session:
            key_record = session.query(KeyVersionModel).filter_by(id=key_id).first()
            if not key_record:
                raise KeyNotFoundError(f"Clave no encontrada: {key_id}")
            return KeyVersion(key_record.id, self._decrypt_key(key_record.master_key_hex), key_record.created_at, key_record.expires_at, bool(key_record.is_active))
    def get_keys_before_date(self, date: datetime) -> list[KeyVersion]:
        with self.Session() as session:
            key_records = session.query(KeyVersionModel).filter(KeyVersionModel.created_at < date).all()
            return [KeyVersion(kr.id, self._decrypt_key(kr.master_key_hex), kr.created_at, kr.expires_at, bool(kr.is_active)) for kr in key_records]
