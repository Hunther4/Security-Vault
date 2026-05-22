import os
import uuid
import tempfile
import logging
from datetime import datetime, timezone, timedelta
from typing import BinaryIO, Tuple, Optional
from repositories import ICryptoProvider, IStorageRepository, ISQLRepository, IKeyRepository, SecurityValidator, KeyRepository
from models import Document

logger = logging.getLogger(__name__)

# Default key rotation interval (7 days)
DEFAULT_ROTATION_INTERVAL_DAYS = 30

class VaultService:
    MAX_FILE_SIZE = 50 * 1024 * 1024

    def __init__(self, crypto: ICryptoProvider, storage: IStorageRepository, sql_db: ISQLRepository, key_repo: Optional[IKeyRepository] = None):
        self._crypto = crypto
        self._storage = storage
        self._sql_db = sql_db
        self._key_repo = key_repo or KeyRepository()
        self._last_rotation = datetime.now(timezone.utc)
    
    def _should_rotate_key(self) -> bool:
        """Check if key should be rotated based on time interval."""
        time_since_rotation = datetime.now(timezone.utc) - self._last_rotation
        return time_since_rotation > timedelta(days=DEFAULT_ROTATION_INTERVAL_DAYS)
    
    def rotate_key_manually(self) -> dict:
        """Manually rotate the master key. Returns new key info."""
        new_key_hex = os.urandom(32).hex()
        new_key = self._key_repo.create_key_version(new_key_hex)
        self._last_rotation = datetime.now(timezone.utc)
        logger.info(f"Key manually rotated. New version: {new_key.id}")
        return {
            "key_id": str(new_key.id),
            "rotated_at": self._last_rotation.isoformat(),
            "message": "Key rotated successfully"
        }

    def upload_secure_document(self, original_filename: str, network_stream: BinaryIO, actor: str) -> Tuple[Document, str]:
        """Upload and encrypt a document.
        
        Returns:
            Tuple of (Document, key_id used for encryption)
        """
        safe_filename = SecurityValidator.sanitize_filename(original_filename)
        header_bytes = network_stream.read(2048)
        # Allow empty files — no magic bytes to validate, treat as plain text
        content_type = "text/plain"
        if header_bytes:
            content_type = SecurityValidator.validate_magic_bytes(header_bytes)
        doc_id = uuid.uuid4()
        
        # Get the active key ID for this document (for future decryption)
        active_key = self._key_repo.get_active_key()
        key_id_used = active_key.id
        
        # Check if we should rotate based on time interval (but don't do it automatically)
        if self._should_rotate_key():
            logger.warning(f"Key rotation recommended (7+ days since last rotation). Use rotate_key_manually() to rotate.")

        # Encrypt using current active key
        with tempfile.TemporaryFile() as temp_enc_stream:
            total_size = self._crypto.encrypt_stream(header_bytes, network_stream, temp_enc_stream, self.MAX_FILE_SIZE)
            temp_enc_stream.seek(0)
            storage_path = self._storage.save_encrypted_stream(doc_id, temp_enc_stream, key_id_used)

        try:
            document = Document(id=doc_id, original_filename=original_filename, safe_filename=safe_filename, content_type=content_type, size_bytes=total_size, created_at=datetime.now(timezone.utc))
            # Save with key_id so we can decrypt later
            self._sql_db.save_metadata(document, storage_path, key_id_used)
            self._sql_db.log_audit(doc_id, "UPLOAD_SUCCESS", actor, key_id_used)
            logger.info(f"Document {doc_id} encrypted with key_id {key_id_used}")
            # NO automatic rotation - key_id is stored for decryption
            return document, key_id_used
        except Exception as e:
            if os.path.exists(storage_path):
                os.remove(storage_path)
            raise RuntimeError(f"Fallo en BD, archivo huérfano eliminado: {e}")

    def download_secure_document(self, document_id: str, actor: str) -> Tuple[str, BinaryIO]:
        """Download and decrypt a document.
        
        Uses the key_id stored with the document to decrypt.
        IMPORTANT: Caller is responsible for closing the returned stream.
        """
        storage_path, original_filename, key_id = self._sql_db.get_metadata(document_id)
        
        # Get the key that was used for this document
        key_version = self._key_repo.get_key_by_id(key_id)
        crypto = self._crypto.__class__(key_hex=key_version.master_key_hex)
        
        # Use TemporaryFile with context manager to ensure proper cleanup
        decrypted_stream = tempfile.TemporaryFile()
        try:
            with self._storage.get_encrypted_stream(storage_path) as encrypted_file:
                crypto.decrypt_stream(encrypted_file, decrypted_stream)
            self._sql_db.log_audit(uuid.UUID(document_id), "DOWNLOAD_SUCCESS", actor, key_id)
            decrypted_stream.seek(0)
            return original_filename, decrypted_stream
        except Exception as e:
            decrypted_stream.close()  # Ensure cleanup on error
            self._sql_db.log_audit(uuid.UUID(document_id), "DECRYPT_FAILED", actor, key_id)
            raise RuntimeError(f"Fallo crítico al desencriptar: {e}")

    def list_documents(self) -> list[dict]:
        """List all documents in the vault."""
        return self._sql_db.list_all()
