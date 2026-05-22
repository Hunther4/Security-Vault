# vault-api Specification

## Purpose

Ensure the API remains responsive and stable during heavy I/O operations.

## Requirements

### Requirement: Event Loop Non-blocking

The system MUST NOT block the FastAPI event loop during file upload or download operations. Critical I/O endpoints MUST be implemented as synchronous functions (`def` instead of `async def`) to utilize FastAPI's external thread pool.

#### Scenario: Responsive API during large upload

- GIVEN a large file upload (e.g., 50MB) is in progress
- WHEN another lightweight API request is made to a different endpoint
- THEN the lightweight request MUST be processed without waiting for the upload to complete.
