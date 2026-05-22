import uuid
import os
import shutil
from unittest.mock import MagicMock
from repositories import LocalStorageRepository

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

def test_save_encrypted_stream_chunked():
    # Setup
    storage_path = "./test_storage"
    repo = LocalStorageRepository(base_path=storage_path)
    doc_id = uuid.uuid4()
    content = b"a" * 1024 * 1024  # 1MB content
    stream = MockStream(content)

    try:
        repo.save_encrypted_stream(doc_id, stream)
        
        # If it's chunked (using copyfileobj), it should call read() multiple times
        # with smaller sizes (usually 16KB or similar).
        # If it's NOT chunked (current: f.write(stream.read())), it calls read() once with -1 or the whole size.
        
        print(f"Read calls: {stream.read_calls}")
        
        # shutil.copyfileobj uses a buffer size, so it should have multiple reads
        assert len(stream.read_calls) > 1, f"Expected multiple read calls for chunking, got {len(stream.read_calls)}"
        
    finally:
        # Cleanup
        if os.path.exists(storage_path):
            shutil.rmtree(storage_path)

if __name__ == "__main__":
    try:
        test_save_encrypted_stream_chunked()
        print("PASSED")
    except AssertionError as e:
        print(f"FAILED: {e}")
        exit(1)
    except Exception as e:
        print(f"ERROR: {e}")
        exit(1)
