package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"testing"
)

func TestEncryptDecryptRoundtrip(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	tests := []struct {
		name    string
		content []byte
	}{
		{"small", []byte("Hello Vault!")},
		{"medium", bytes.Repeat([]byte("A"), 100*1024)},
		{"empty", []byte{}},
		{"all bytes", func() []byte {
			b := make([]byte, 256)
			for i := range b {
				b[i] = byte(i)
			}
			return b
		}()},
		{"large", bytes.Repeat([]byte("0123456789"), 10*1024)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var encBuf bytes.Buffer
			input := bytes.NewReader(tt.content)

			_, err := EncryptStream(key, input, &encBuf)
			if err != nil {
				t.Fatalf("encrypt: %v", err)
			}

			var decBuf bytes.Buffer
			err = DecryptStream(key, &encBuf, &decBuf)
			if err != nil {
				t.Fatalf("decrypt: %v", err)
			}

			if !bytes.Equal(decBuf.Bytes(), tt.content) {
				t.Fatalf("roundtrip mismatch: got %d bytes, want %d", len(decBuf.Bytes()), len(tt.content))
			}
		})
	}
}

func TestDecryptWithWrongKey(t *testing.T) {
	content := []byte("secret data")
	key := make([]byte, 32)
	rand.Read(key)
	wrongKey := make([]byte, 32)
	rand.Read(wrongKey)

	var encBuf bytes.Buffer
	_, err := EncryptStream(key, bytes.NewReader(content), &encBuf)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	var decBuf bytes.Buffer
	err = DecryptStream(wrongKey, &encBuf, &decBuf)
	if err == nil {
		t.Fatal("expected error decrypting with wrong key, got nil")
	}
}

func TestStreamingLargeFile(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	// 5 MB of data
	size := 5 * 1024 * 1024
	content := make([]byte, size)
	rand.Read(content)

	var encBuf bytes.Buffer
	n, err := EncryptStream(key, bytes.NewReader(content), &encBuf)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if n != int64(size) {
		t.Fatalf("expected %d bytes, got %d", size, n)
	}

	var decBuf bytes.Buffer
	err = DecryptStream(key, &encBuf, &decBuf)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}

	if decBuf.Len() != size {
		t.Fatalf("size mismatch: %d vs %d", decBuf.Len(), size)
	}
}

func TestKeySizeValidation(t *testing.T) {
	key := make([]byte, 16) // 128-bit — wrong
	_, err := EncryptStream(key, bytes.NewReader([]byte("test")), io.Discard)
	if err == nil {
		t.Fatal("expected error with 128-bit key")
	}

	err = DecryptStream(key, bytes.NewReader([]byte("test")), io.Discard)
	if err == nil {
		t.Fatal("expected error with 128-bit key on decrypt")
	}
}

func TestDecryptForgedLength(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	// Create a forged header: 2GB length
	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, 2*1024*1024*1024)
	
	input := bytes.NewReader(lenBuf)
	var output bytes.Buffer
	
	err := DecryptStream(key, input, &output)
	if err == nil {
		t.Fatal("expected error for forged length, got nil")
	}
}

func TestEncryptWriteError(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	// Create a writer that always returns an error
	errorWriter := &errWriter{}
	
	_, err := EncryptStream(key, bytes.NewReader([]byte("test data")), errorWriter)
	if err == nil {
		t.Fatal("expected error when writer fails, got nil")
	}
}

type errWriter struct{}
func (e *errWriter) Write(p []byte) (n int, err error) {
	return 0, fmt.Errorf("simulated write error")
}

func TestVersion1Roundtrip(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	content := []byte("Hello Version 1 Vault!")
	
	var encBuf bytes.Buffer
	_, err := EncryptStream(key, bytes.NewReader(content), &encBuf)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	
	// Verify version byte
	if encBuf.Bytes()[0] != 1 {
		t.Fatalf("expected version byte 1, got %v", encBuf.Bytes()[0])
	}
	
	var decBuf bytes.Buffer
	err = DecryptStream(key, &encBuf, &decBuf)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	
	if !bytes.Equal(decBuf.Bytes(), content) {
		t.Fatalf("roundtrip mismatch: got %s, want %s", decBuf.String(), content)
	}
}

func TestBackwardCompatibilityV0(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	content := []byte("Legacy v0 content")
	
	// Create a v0 file manually (no version byte, no AAD)
	block, _ := aes.NewCipher(key)
	aesgcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, 12)
	rand.Read(nonce)
	ciphertext := aesgcm.Seal(nil, nonce, content, nil)
	
	var v0Buf bytes.Buffer
	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, uint32(len(ciphertext)))
	v0Buf.Write(lenBuf)
	v0Buf.Write(nonce)
	v0Buf.Write(ciphertext)
	
	var decBuf bytes.Buffer
	err := DecryptStream(key, &v0Buf, &decBuf)
	if err != nil {
		t.Fatalf("decrypt v0: %v", err)
	}
	
	if !bytes.Equal(decBuf.Bytes(), content) {
		t.Fatalf("v0 roundtrip mismatch")
	}
}
