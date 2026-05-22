import os
import psutil
import uuid
import shutil
from io import BytesIO
from repositories import AES256GCMChunkedProvider, LocalStorageRepository, SQLiteRepository, KeyRepository
from services import VaultService

def test_ram_usage():
    # Setup
    storage_path = "./ram_test_storage"
    db_path = "ram_test.db"
    os.makedirs(storage_path, exist_ok=True)
    
    kr = KeyRepository(db_url=f"sqlite:///{db_path}")
    mk = "0" * 64
    kr.create_key_version(mk)
    
    crypto = AES256GCMChunkedProvider(key_hex=mk)
    storage = LocalStorageRepository(base_path=storage_path)
    sql_db = SQLiteRepository(db_url=f"sqlite:///{db_path}")
    
    vault = VaultService(crypto=crypto, storage=storage, sql_db=sql_db, key_repo=kr)
    
    # 40MB file to test memory
    size = 40 * 1024 * 1024
    content = b"a" * size
    input_stream = BytesIO(content)
    
    process = psutil.Process(os.getpid())
    mem_before = process.memory_info().rss
    
    # Upload
    doc, _ = vault.upload_secure_document("large_file.bin", input_stream, actor="tester")
    
    mem_after = process.memory_info().rss
    mem_diff = (mem_after - mem_before) / (1024 * 1024)
    
    print(f"RAM difference: {mem_diff:.2f} MB")
    # We expect the memory diff to be much smaller than the file size (e.g., < 10MB)
    assert mem_diff < 20, f"RAM usage spike too high: {mem_diff:.2f} MB"
    
    # Download
    filename, dec_stream = vault.download_secure_document(str(doc.id), actor="tester")
    
    # Read in chunks to avoid loading the result into memory
    while True:
        chunk = dec_stream.read(64 * 1024)
        if not chunk: break
    
    mem_final = process.memory_info().rss
    mem_diff_down = (mem_final - mem_before) / (1024 * 1024)
    print(f"Final RAM difference: {mem_diff_down:.2f} MB")
    assert mem_diff_down < 20, f"RAM usage spike during download too high: {mem_diff_down:.2f} MB"
    
    # Cleanup
    shutil.rmtree(storage_path)
    os.remove(db_path)
    print("RAM Usage Test PASSED")

def test_chunk_manipulation():
    key_hex = "0" * 64
    crypto = AES256GCMChunkedProvider(key_hex=key_hex)
    
    # Create a v1 file with multiple chunks
    content = b"chunk0" + (b"chunk" * 20000) # ~100KB, will be split into 2 chunks
    output = BytesIO()
    crypto.encrypt_stream(b"h", BytesIO(content), output, max_size=10*1024*1024)
    
    data = bytearray(output.getvalue())
    
    # v1 format: [version:1][len1:4][nonce1:12][ct1:len1][len2:4][nonce2:12][ct2:len2]...
    # Let's find the start of the second chunk
    # First chunk len is at data[1:5]
    len1 = int.from_bytes(data[1:5], 'big')
    chunk1_end = 1 + 4 + 12 + len1
    
    # Swap chunk 1 and chunk 2 (simplified: just change AAD of second chunk by modifying the file is hard,
    # so we just swap the ciphertext parts)
    # But the easiest way to detect manipulation is to swap the whole chunks (len+nonce+ct)
    
    # Let's just swap some bytes in the middle of the second chunk's ciphertext
    # This should trigger GCM authentication failure
    data[chunk1_end + 20] = data[chunk1_end + 20] ^ 0xFF
    
    dec_output = BytesIO()
    try:
        crypto.decrypt_stream(BytesIO(data), dec_output)
        # If it doesn't raise an error, it failed to detect manipulation
        # However, AESGCM.decrypt in cryptography raises InvalidTag
    except Exception as e:
        print(f"Detected manipulation: {e}")
        return
    
    # If we reached here, it failed to detect
    raise AssertionError("Failed to detect chunk manipulation")

if __name__ == "__main__":
    try:
        test_ram_usage()
        test_chunk_manipulation()
        print("All Verification tests PASSED")
    except AssertionError as e:
        print(f"FAILED: {e}")
        exit(1)
    except Exception as e:
        print(f"ERROR: {e}")
        exit(1)
