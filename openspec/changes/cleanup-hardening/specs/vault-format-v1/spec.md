# vault-format-v1 Specification

## Purpose

Provide a versioned vault format with manipulation detection.

## Requirements

### Requirement: Versioned Header

Encrypted files MUST start with a version byte. The system MUST support both Version 0 (legacy) and Version 1 (hardened).

#### Scenario: Backward compatibility

- GIVEN a Vault Format v0 file
- WHEN the system attempts to decrypt it
- THEN the decryption MUST succeed.

### Requirement: Chunk-Indexed AAD

All new files (Version 1) MUST include a 4-byte sequence number in the Additional Authenticated Data (AAD) for each chunk. The sequence number MUST match the chunk's position in the file.

#### Scenario: Manipulation detection (swapped chunks)

- GIVEN a Vault Format v1 file
- WHEN two chunks are swapped or one is deleted
- THEN the decryption of the affected chunks MUST fail authentication.
