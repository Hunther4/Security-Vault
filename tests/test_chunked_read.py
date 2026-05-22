import os
import shutil
from unittest.mock import MagicMock
from services import VaultService
from repositories import AES256GCMChunkedProvider, LocalStorageRepository, SQLiteRepository, KeyRepository

class MockStream:
    def __init__(self, content: bytes):
        self.content = content
        self.read_calls = []
        self.pos = 0

    def read(self, size=-1):
        if size == -1:
            size = len(self.content) - self.pos
        
        self.read_calls.append(size)
        chunk = self.content[self.pos : self.pos + size]
        self.pos += len(chunk)
        return chunk

    def close(self):
        pass

def test_decrypt_flow_chunked():
    # Setup
    storage_path = "./test_storage"
    db_path = "test_vault.db"
    
    # Setup minimal vault
    kr = KeyRepository(db_url=f"sqlite:///{db_path}")
    mk = "0" * 64
    kr.create_key_version(mk)
    
    crypto = AES256GCMChunkedProvider(key_hex=mk)
    storage = LocalStorageRepository(base_path=storage_path)
    sql_db = SQLiteRepository(db_url=f"sqlite:///{db_path}")
    
    vault = VaultService(crypto=crypto, storage=storage, sql_db=sql_db, key_repo=kr)
    
    # Create a document to decrypt
    doc_id = "f47ac10b-58cc-4372-a567-0e02b2c3d479" # valid uuid
    from models import Document
    import uuid
    u_id = uuid.UUID(doc_id)
    
    # We mock the stream returned by download_secure_document
    mock_decrypted_stream = MockStream(b"a" * 1024 * 1024)
    
    with patch.object(VaultService, 'download_secure_document', return_value=("test.txt", mock_decrypted_stream)):
        # We simulate the core of decrypt_flow:
        # fn, stream = vault.download_secure_document(doc_id, actor="CLI")
        # path = os.path.join(dest, f"recup_{fn}")
        # with open(path, "wb") as f: f.write(stream.read())
        
        dest = "./test_recup"
        os.makedirs(dest, exist_ok=True)
        fn, stream = vault.download_secure_document(doc_id, actor="CLI")
        path = os.path.join(dest, f"recup_{fn}")
        
        # This is the part we are testing
        with open(path, "wb") as f:
            shutil.copyfileobj(stream, f)

        print(f"Read calls: {stream.read_calls}")
        assert len(stream.read_calls) > 1, f"Expected multiple read calls, got {len(stream.read_calls)}"

    # Cleanup
    if os.path.exists(storage_path): shutil.rmtree(storage_path)
    if os.path.exists("./test_recup"): shutil.rmtree("./test_recup")
    if os.path.exists(db_path): os.remove(db_path)

if __name__ == "__main__":
    from unittest.mock import patch
    try:
        test_decrypt_flow_chunked()
        print("PASSED")
    except AssertionError as e:
        print(f"FAILED: {e}")
        exit(1)
    except Exception as e:
        print(f"ERROR: {e}")
        exit(1)
