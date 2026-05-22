# Proposal: Clean-up and Hardening

## Intent

Harden the vault against DoS, memory exhaustion, and chunk-manipulation attacks, and fix FastAPI event loop blocking to ensure stability under load.

## Scope

### In Scope
- `api.py`: Fix event loop blocking.
- `repositories.py`: Implement chunked writing and Vault Format v1 (Sequence Number AAD).
- `main.py`: Implement chunked recovery reads.
- `internal/crypto/aes_gcm.go`: Fix DoS vulnerability, error handling, and implement Vault Format v1 (Sequence Number AAD).

### Out of Scope
- General performance optimizations unrelated to memory or DoS.
- Changing the underlying encryption algorithm.

## Capabilities

### New Capabilities
- `vault-format-v1`: Support for versioned vault files with chunk-indexed AAD for manipulation detection.

### Modified Capabilities
- `vault-storage`: Transition to chunked I/O for constant memory usage.
- `vault-api`: Prevent event loop blocking during large file transfers.
- `vault-recovery`: Transition to chunked reads.
- `crypto-aes-gcm`: Implement `MaxChunkSize` guards and AAD support for version 1.

## Approach

- **Event Loop**: Transition critical endpoints from `async def` to `def` to utilize FastAPI's thread pool, preventing event loop starvation during heavy I/O.
- **Memory Management**: Implement `while chunk := f.read(CHUNK_SIZE)` patterns across Python storage and recovery to ensure constant memory footprint.
- **Go Hardening**: In `internal/crypto/aes_gcm.go`, add `MaxChunkSize` checks to prevent OOM panics from forged length headers and validate `Write()` return values.
- **Format Versioning**: Introduce a version byte at the start of encrypted files:
  - **Version 0**: Legacy (nil AAD).
  - **Version 1**: Hardened (4-byte chunk index in AAD).
- **Compatibility**: Align AAD logic between the Go CLI and Python API to maintain cross-platform decryption.

## Affected Areas

| Area | Impact | Description |
|------|--------|-------------|
| `api.py` | Modified | Critical endpoints converted to `def`. |
| `repositories.py` | Modified | Chunked writing and v1 format logic. |
| `main.py` | Modified | Chunked recovery reads logic. |
| `internal/crypto/aes_gcm.go` | Modified | DoS guards and v1 format implementation. |

## Risks

| Risk | Likelihood | Mitigation |
|------|------------|------------|
| Compatibility Regression | Low | Version byte check ensures v0 files remain decryptable. |
| I/O Performance Drop | Low | Optimize `CHUNK_SIZE` for balanced throughput. |

## Rollback Plan

Revert changes in `api.py`, `repositories.py`, `main.py`, and `internal/crypto/aes_gcm.go` via git. Since v0 files are preserved and backward compatibility is maintained, no data loss will occur.

## Dependencies

- None.

## Success Criteria

- [ ] Zero event loop blocking during large uploads/downloads.
- [ ] Constant memory usage regardless of file size.
- [ ] Go client resists forged length headers (no OOM panics).
- [ ] Detection of chunk reordering/deletion via AAD authentication failure.
- [ ] Ability to decrypt both v0 and v1 files.
