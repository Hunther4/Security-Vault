import asyncio
import time
import pytest
import httpx
import sys
from unittest.mock import MagicMock, patch

# Mock pythonjsonlogger before importing api
mock_json_logger = MagicMock()
sys.modules["pythonjsonlogger"] = MagicMock()
sys.modules["pythonjsonlogger.jsonlogger"] = mock_json_logger

from fastapi import FastAPI
from fastapi.testclient import TestClient
from api import app
from services import VaultService

# Use AsyncClient for concurrent requests
@pytest.mark.asyncio
async def test_upload_blocks_event_loop():
    # We need to mock VaultService.upload_secure_document to be blocking
    with patch("services.VaultService.upload_secure_document") as mock_upload:
        def blocking_upload(*args, **kwargs):
            time.sleep(1) # Simulate blocking I/O
            return (MagicMock(), None)
        
        mock_upload.side_effect = blocking_upload

        async with httpx.AsyncClient(app=app, base_url="http://test") as client:
            # We use a dummy API key since verify_api_key checks it
            # We need to add it to the API_KEYS set in api.py or mock verify_api_key
            with patch("api.API_KEYS", {"test-key"}):
                # Start the blocking request
                start_time = time.perf_counter()
                
                # Task 1: Blocking upload
                upload_task = asyncio.create_task(
                    client.post(
                        "/upload", 
                        headers={"X-API-Key": "test-key"},
                        files={"file": ("test.txt", b"content")}
                    )
                )
                
                # Give it a moment to start and hit the blocking call
                await asyncio.sleep(0.1)
                
                # Task 2: Lightweight health check
                health_task = asyncio.create_task(
                    client.get("/health", headers={"X-API-Key": "test-key"})
                )
                
                # Wait for health check to finish
                health_response = await health_task
                end_time = time.perf_counter()
                
                # Wait for upload to finish to clean up
                await upload_task
                
                duration = end_time - start_time
                
                # If the loop was blocked, the health check had to wait for the upload
                # so duration will be at least 1 second.
                # If not blocked, duration should be much smaller (~0.1s + overhead).
                assert duration < 0.5, f"Event loop blocked! Health check took {duration:.2f}s"

if __name__ == "__main__":
    # This allows running the file directly for a quick check
    import pytest
    pytest.main([__file__])
