import asyncio
import time
import sys
from unittest.mock import MagicMock, patch

# Mock pythonjsonlogger before importing api
sys.modules["pythonjsonlogger"] = MagicMock()
sys.modules["pythonjsonlogger.jsonlogger"] = MagicMock()

import httpx
from api import app

async def main():
    with patch("services.VaultService.upload_secure_document") as mock_upload:
        def blocking_upload(*args, **kwargs):
            print("--- BLOCKING START ---")
            time.sleep(2) # Simulate blocking I/O
            print("--- BLOCKING END ---")
            return (MagicMock(), None)
        
        mock_upload.side_effect = blocking_upload

        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            with patch("api.API_KEYS", {"test-key"}):
                print("Starting concurrent requests...")
                start_time = time.perf_counter()
                
                # Task 1: Blocking upload
                upload_task = asyncio.create_task(
                    client.post(
                        "/upload", 
                        headers={"X-API-Key": "test-key"},
                        files={"file": ("test.txt", b"content")}
                    )
                )
                
                await asyncio.sleep(0.1)
                
                # Task 2: Lightweight health check
                health_task = asyncio.create_task(
                    client.get("/health", headers={"X-API-Key": "test-key"})
                )
                
                health_response = await health_task
                end_time = time.perf_counter()
                
                await upload_task
                
                duration = end_time - start_time
                print(f"Health check duration: {duration:.2f}s")
                
                if duration >= 1.0:
                    print("FAILED: Event loop is BLOCKED")
                    sys.exit(1)
                else:
                    print("PASSED: Event loop is NOT blocked")
                    sys.exit(0)

if __name__ == "__main__":
    asyncio.run(main())
