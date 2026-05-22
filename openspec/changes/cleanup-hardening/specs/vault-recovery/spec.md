# vault-recovery Specification

## Purpose

Ensure constant memory usage during vault file recovery.

## Requirements

### Requirement: Chunked File Reading

The system MUST read encrypted files from disk in fixed-size chunks. Memory usage MUST remain constant regardless of the total file size.

#### Scenario: Constant memory during large recovery

- GIVEN a large encrypted vault file (e.g., 50MB)
- WHEN the recovery operation is executed
- THEN the RAM usage MUST NOT spike proportional to the file size.
