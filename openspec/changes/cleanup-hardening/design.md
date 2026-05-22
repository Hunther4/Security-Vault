# Design: Clean-up and Hardening

## Technical Approach

The goal is to transform the vault from a prototype that loads large files into memory into a production-ready system with constant memory overhead and protection against common cryptographic attacks (chunk manipulation and memory exhaustion).

The strategy is centered on **Stream-based I/O** and **Versioned Format**. By introducing a version byte at the start of vault files, we can implement a "Hardened" format (v1) that uses the chunk sequence number as Additional Authenticated Data (AAD), preventing attackers from swapping or deleting chunks.

## Architecture Decisions

| Decision | Choice | Alternatives | Rationale |
|----------|--------|--------------|------------|
| **FastAPI Concurrency** | Synchronous `def` routes | `async def` + `run_in_executor` | Simpler implementation; FastAPI handles thread pool automatically for `def` routes, preventing event loop starvation during heavy disk I/O. |
| **I/O Pattern** | `shutil.copyfileobj` / `while` loops | `f.read()` / `f.write()` | Ensures memory usage remains constant ($\approx$ 64KB) regardless of file size (O(1) memory complexity). |
| **Format Versioning** | 1-byte prefix | Metadata file | Minimal overhead, self-contained vault files, and easy backward compatibility check. |
| **Manipulation Guard** | Sequence Number AAD | HMAC of whole file | Sequence numbers in AAD allow chunk-by-chunk authentication and prevent "cut-and-paste" attacks on chunks without needing to read the whole file first. |

## Data Flow

### Encryption (v1)
`UploadFile` $\rightarrow$ `VaultService` $\rightarrow$ `AES256GCMChunkedProvider` $\rightarrow$ `TemporaryFile` $\rightarrow$ `LocalStorageRepository` $\rightarrow$ `.enc` file

1. Write Version Byte `0x01`.
2. For each chunk:
   - Generate random Nonce.
   - AAD = $\text{BigEndian}(\text{chunk\_index})$.
   - Ciphertext = $\text{AES-GCM}(\text{Key, Nonce, Plaintext, AAD})$.
   - Write: `[Length][Nonce][Ciphertext]`.

### Decryption (v1)
`.enc` file $\rightarrow$ `LocalStorageRepository` $\rightarrow$ `AES256GCMChunkedProvider` $\rightarrow$ `TemporaryFile` $\rightarrow$ `StreamingResponse` / `File`

1. Read Version Byte.
2. If `0x01`:
   - For each chunk:
     - AAD = $\text{BigEndian}(\text{chunk\_index})$.
     - Plaintext = $\text{AES-GCM-Open}(\text{Key, Nonce, Ciphertext, AAD})$.
     - If authentication fails $\rightarrow$ throw `InvalidTag`.
3. If `0x00`: Use legacy decryption (AAD = `nil`).

## File Changes

| File | Action | Description |
|------|--------|-------------|
| `api.py` | Modify | Convert `/upload` and `/download/{id}` to `def` instead of `async def`. |
| `repositories.py` | Modify | `AES256GCMChunkedProvider`: Implement Version Byte and Sequence AAD. `LocalStorageRepository.save_encrypted_stream`: Replace `f.write(stream.read())` with chunked copying. |
| `main.py` | Modify | `decrypt_flow`: Replace `f.write(stream.read())` with chunked copying. |
| `internal/crypto/aes_gcm.go` | Modify | Add `MaxChunkSize` guard. Implement Version Byte and Sequence AAD. Add error checks to `Write()` calls. |

## Interfaces / Contracts

### Vault Format v1
```
[1 Byte: Version]
[4 Bytes: Chunk 0 Length][12 Bytes: Nonce][N Bytes: Ciphertext + Tag] (AAD: 0)
[4 Bytes: Chunk 1 Length][12 Bytes: Nonce][N Bytes: Ciphertext + Tag] (AAD: 1)
...
```

### Go `DecryptStream` Guard
```go
if chunkSize > MaxChunkSize {
    return fmt.Errorf("chunk size %d exceeds maximum allowed %d", chunkSize, MaxChunkSize)
}
```

## Testing Strategy

| Layer | What to Test | Approach |
|-------|-------------|----------|
| **Integration (PY)** | Memory Stability | Upload a 100MB file and monitor RSS memory using `psutil`. Expect flat line. |
| **Security (PY)** | Chunk Manipulation | Encrypt v1 file $\rightarrow$ swap two chunks in bytes $\rightarrow$ verify `InvalidTag` exception. |
| **Security (GO)** | DoS Resistance | Pass a file with header `0x00` and length `0x7FFFFFFF` $\rightarrow$ verify immediate error without OOM. |
| **Compatibility** | v0 $\rightarrow$ v1 | Encrypt file with v0 $\rightarrow$ decrypt with v1 code $\rightarrow$ verify success. |

## Migration / Rollout

- **No migration required**.
- Version byte ensures that old v0 files are decrypted using legacy logic (AAD = `nil`).
- All new uploads will use v1.
