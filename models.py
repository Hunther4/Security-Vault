from dataclasses import dataclass
from datetime import datetime
import uuid
from sqlalchemy import Column, String, Integer, DateTime
from sqlalchemy.orm import declarative_base

Base = declarative_base()

@dataclass(frozen=True)
class KeyVersion:
    id: int
    master_key_hex: str
    created_at: datetime
    expires_at: datetime
    is_active: bool = False

@dataclass(frozen=True)
class Document:
    id: uuid.UUID
    original_filename: str
    safe_filename: str
    content_type: str
    size_bytes: int
    created_at: datetime

class DocumentModel(Base):
    __tablename__ = 'documents'
    id = Column(String, primary_key=True)
    original_filename = Column(String)
    safe_filename = Column(String)
    content_type = Column(String)
    size_bytes = Column(Integer)
    storage_path = Column(String)
    key_id = Column(String, nullable=True)  # Key version used for encryption
    created_at = Column(DateTime)

class AuditLogModel(Base):
    __tablename__ = 'audit_logs'
    log_id = Column(String, primary_key=True)
    document_id = Column(String)
    action = Column(String)
    actor = Column(String)
    key_id = Column(String, nullable=True)  # Key used for operation
    timestamp = Column(DateTime)

class KeyVersionModel(Base):
    __tablename__ = 'key_versions'
    id = Column(Integer, primary_key=True, autoincrement=True)
    master_key_hex = Column(String(255), nullable=False)
    created_at = Column(DateTime, default=datetime.now)
    expires_at = Column(DateTime, nullable=False)
    is_active = Column(Integer, default=0)
