import unittest
import os
import shutil
from sqlalchemy import create_engine
from services import VaultService
from repositories import AES256GCMChunkedProvider, LocalStorageRepository, SQLiteRepository, KeyRepository
import io

class TestPortfolioVault(unittest.TestCase):
    def setUp(self):
        self.test_dir = "./test_storage"
        os.makedirs(self.test_dir, exist_ok=True)
        self.db_path = "test_vault.db"
        self.master_key = os.urandom(32).hex()
        
        # Shared engine for all repos
        self._engine = create_engine(f"sqlite:///{self.db_path}")
        
        # Init repo
        self.key_repo = KeyRepository(db_url=f"sqlite:///{self.db_path}", engine=self._engine)
        self.key_repo.create_key_version(self.master_key)
        
        self.vault = VaultService(
            crypto=AES256GCMChunkedProvider(key_hex=self.master_key),
            storage=LocalStorageRepository(base_path=self.test_dir),
            sql_db=SQLiteRepository(db_url=f"sqlite:///{self.db_path}", engine=self._engine),
            key_repo=self.key_repo
        )

    def tearDown(self):
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)
        if os.path.exists(self.db_path):
            os.remove(self.db_path)

    def test_upload_and_download(self):
        content = b"Este es un documento confidencial."
        file_stream = io.BytesIO(content)
        
        doc, _ = self.vault.upload_secure_document("test.txt", file_stream, actor="Admin_User")
        self.assertIsNotNone(doc.id)
        
        filename, downloaded_stream = self.vault.download_secure_document(str(doc.id), actor="Admin_User")
        self.assertEqual(downloaded_stream.read(), content)

    def test_encryption_decryption_roundtrip(self):
        """Test that encryption and decryption work correctly together."""
        # Test with various content sizes
        test_contents = [
            b"Small content",
            b"Medium content " * 100,
            b"\x00\x01\x02\x03\x04\x05" * 1000,  # Binary content
            b"",  # Edge case: empty
            bytes(range(256)),  # All possible byte values
        ]
        
        for i, content in enumerate(test_contents):
            file_stream = io.BytesIO(content)
            filename = f"test_roundtrip_{i}.dat"
            
            # Upload
            doc, _ = self.vault.upload_secure_document(filename, file_stream, actor="Test_User")
            self.assertIsNotNone(doc.id)
            
            # Download and verify
            retrieved_filename, downloaded_stream = self.vault.download_secure_document(
                str(doc.id), actor="Test_User"
            )
            retrieved_content = downloaded_stream.read()
            
            self.assertEqual(retrieved_content, content, 
                           f"Roundtrip failed for test case {i}")
            downloaded_stream.close()

if __name__ == "__main__":
    unittest.main()
