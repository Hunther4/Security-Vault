package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
)

const (
	ChunkSize = 64 * 1024 // 64KB — must match Python's CHUNK_SIZE
	MaxChunkSize = 1024 * 1024 // 1MB — prevent OOM from forged headers
	NonceSize = 12        // GCM standard nonce
)

// EncryptStream encrypts data from input using AES-256-GCM and writes to output
// in the same format as the Python implementation:
// [4-byte chunk length][12-byte nonce][ciphertext + 16-byte tag]...
func EncryptStream(key []byte, input io.Reader, output io.Writer) (int64, error) {
	if len(key) != 32 {
		return 0, fmt.Errorf("key must be 32 bytes (256-bit), got %d", len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return 0, fmt.Errorf("aes new cipher: %w", err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return 0, fmt.Errorf("gcm new: %w", err)
	}

	// Write version byte (v1)
	if _, err := output.Write([]byte{1}); err != nil {
		return 0, fmt.Errorf("write version: %w", err)
	}

	var total int64
	buf := make([]byte, ChunkSize)
	var chunkIdx uint32
	for {
		n, err := input.Read(buf)
		if n > 0 {
			chunk := buf[:n]
			nonce := make([]byte, NonceSize)
			if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
				return total, fmt.Errorf("nonce generation: %w", err)
			}

			// Sequence number as AAD (4 bytes, BigEndian)
			aad := make([]byte, 4)
			binary.BigEndian.PutUint32(aad, chunkIdx)

			ciphertext := aesgcm.Seal(nil, nonce, chunk, aad)

			// Write [4-byte length][nonce][ciphertext]
			lenBuf := make([]byte, 4)
			binary.BigEndian.PutUint32(lenBuf, uint32(len(ciphertext)))
			if _, err := output.Write(lenBuf); err != nil {
				return total, fmt.Errorf("write length: %w", err)
			}
			if _, err := output.Write(nonce); err != nil {
				return total, fmt.Errorf("write nonce: %w", err)
			}
			if _, err := output.Write(ciphertext); err != nil {
				return total, fmt.Errorf("write ciphertext: %w", err)
			}

			total += int64(n)
			chunkIdx++
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return total, fmt.Errorf("read error: %w", err)
		}
	}

	return total, nil
}

// DecryptStream reads an encrypted stream in Python-compatible format
// and writes the decrypted data to output.
func DecryptStream(key []byte, input io.Reader, output io.Writer) error {
	if len(key) != 32 {
		return fmt.Errorf("key must be 32 bytes (256-bit), got %d", len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("aes new cipher: %w", err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("gcm new: %w", err)
	}

	// Read version byte
	versionBuf := make([]byte, 1)
	if _, err := io.ReadFull(input, versionBuf); err != nil {
		if err == io.EOF {
			return nil
		}
		return fmt.Errorf("read version: %w", err)
	}
	version := versionBuf[0]

	// Handle v0 backward compatibility: if not 1, it's the first byte of the first chunk length
	if version != 1 {
		// Reconstruct first chunk length
		lenBuf := make([]byte, 4)
		lenBuf[0] = version
		if _, err := io.ReadFull(input, lenBuf[1:]); err != nil {
			return fmt.Errorf("read first chunk length: %w", err)
		}
		chunkSize := binary.BigEndian.Uint32(lenBuf)

		nonce := make([]byte, NonceSize)
		if _, err := io.ReadFull(input, nonce); err != nil {
			return fmt.Errorf("read nonce: %w", err)
		}

		ciphertext := make([]byte, chunkSize)
		if _, err := io.ReadFull(input, ciphertext); err != nil {
			return fmt.Errorf("read ciphertext: %w", err)
		}

		plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			return fmt.Errorf("decrypt chunk: %w", err)
		}

		if _, err := output.Write(plaintext); err != nil {
			return fmt.Errorf("write plaintext: %w", err)
		}

		// Continue v0 processing
		for {
			lenBuf := make([]byte, 4)
			if _, err := io.ReadFull(input, lenBuf); err != nil {
				if err == io.EOF {
					break
				}
				return fmt.Errorf("read chunk length: %w", err)
			}
			chunkSize := binary.BigEndian.Uint32(lenBuf)
			nonce := make([]byte, NonceSize)
			if _, err := io.ReadFull(input, nonce); err != nil {
				return fmt.Errorf("read nonce: %w", err)
			}
			ciphertext := make([]byte, chunkSize)
			if _, err := io.ReadFull(input, ciphertext); err != nil {
				return fmt.Errorf("read ciphertext: %w", err)
			}
			plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
			if err != nil {
				return fmt.Errorf("decrypt chunk: %w", err)
			}
			if _, err := output.Write(plaintext); err != nil {
				return fmt.Errorf("write plaintext: %w", err)
			}
		}
		return nil
	}

	// Version 1: use sequence numbers as AAD
	var chunkIdx uint32
	for {
		lenBuf := make([]byte, 4)
		if _, err := io.ReadFull(input, lenBuf); err != nil {
			if err == io.EOF {
				break
			}
			return fmt.Errorf("read chunk length: %w", err)
		}
		chunkSize := binary.BigEndian.Uint32(lenBuf)
		if chunkSize > MaxChunkSize {
			return fmt.Errorf("chunk size %d exceeds maximum allowed %d", chunkSize, MaxChunkSize)
		}
		nonce := make([]byte, NonceSize)
		if _, err := io.ReadFull(input, nonce); err != nil {
			return fmt.Errorf("read nonce: %w", err)
		}
		ciphertext := make([]byte, chunkSize)
		if _, err := io.ReadFull(input, ciphertext); err != nil {
			return fmt.Errorf("read ciphertext: %w", err)
		}
		aad := make([]byte, 4)
		binary.BigEndian.PutUint32(aad, chunkIdx)
		plaintext, err := aesgcm.Open(nil, nonce, ciphertext, aad)
		if err != nil {
			return fmt.Errorf("decrypt chunk: %w", err)
		}
		if _, err := output.Write(plaintext); err != nil {
			return fmt.Errorf("write plaintext: %w", err)
		}
		chunkIdx++
	}

	return nil
}

