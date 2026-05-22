import uuid
import os
import shutil
from io import BytesIO
from repositories import AES256GCMChunkedProvider

def test_v1_roundtrip():
    key_hex = "0" * 64
    crypto = AES256GCMChunkedProvider(key_hex=key_hex)
    content = b"Hello Version 1 Python Vault!"
    header = b"header"
    
    output = BytesIO()
    crypto.encrypt_stream(header, BytesIO(b"remaining"), output, max_size=10*1024*1024)
    # Wait, the encrypt_stream in my test should use the actual content
    
    # Let's use a proper stream
    input_stream = BytesIO(content)
    output = BytesIO()
    crypto.encrypt_stream(b"h", input_stream, output, max_size=10*1024*1024)
    
    # Check version byte
    data = output.getvalue()
    assert data[0] == 1, f"Expected version byte 1, got {data[0]}"
    
    dec_output = BytesIO()
    crypto.decrypt_stream(BytesIO(data), dec_output)
    
    # The decrypt_stream in the provider decrypts the whole thing, including header
    # but my encrypt_stream implementation treats header as the first chunk.
    # So the decrypted result should be header + content.
    result = dec_output.getvalue()
    assert result == b"h" + content, f"Roundtrip mismatch: {result}"
    print("v1 Roundtrip PASSED")

def test_v0_backward_compatibility():
    key_hex = "0" * 64
    crypto = AES256GCMChunkedProvider(key_hex=key_hex)
    
    # Create a v0 stream manually
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    aesgcm = AESGCM(bytes.fromhex(key_hex))
    nonce = os.urandom(12)
    content = b"Legacy v0 content"
    ciphertext = aesgcm.encrypt(nonce, content, None)
    
    v0_data = len(ciphertext).to_bytes(4, 'big') + nonce + ciphertext
    
    dec_output = BytesIO()
    crypto.decrypt_stream(BytesIO(v0_data), dec_output)
    
    assert dec_output.getvalue() == content, "v0 Backward compatibility FAILED"
    print("v0 Backward Compatibility PASSED")

if __name__ == "__main__":
    try:
        test_v1_roundtrip()
        test_v0_backward_compatibility()
        print("All Python Format v1 tests PASSED")
    except AssertionError as e:
        print(f"FAILED: {e}")
        exit(1)
    except Exception as e:
        print(f"ERROR: {e}")
        exit(1)
