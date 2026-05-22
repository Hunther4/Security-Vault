# crypto-aes-gcm Specification

## Purpose

Harden the Go encryption implementation against DoS and manipulation.

## Requirements

### Requirement: Forged Length Guard

The system MUST validate the length header of encrypted chunks. Chunks exceeding a predefined `MaxChunkSize` MUST be rejected immediately.

#### Scenario: Forged length header rejection

- GIVEN a vault file with a forged length header (e.g., 2GB)
- WHEN the Go client attempts to decrypt the file
- THEN the system MUST return an error and MUST NOT allocate memory proportional to the forged length (no OOM).
