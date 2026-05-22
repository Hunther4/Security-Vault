package cli

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/Hunther4/Security-Vault/internal/config"
	"github.com/spf13/cobra"
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize the vault (DB, storage, config, master key)",
	RunE: func(cmd *cobra.Command, args []string) error {
		logIfNotJSON("🔐 Initializing vault...")

		// 1. Create storage directory
		storageDir := "./secure_storage"
		if err := os.MkdirAll(storageDir, 0o750); err != nil {
			return fmt.Errorf("create storage dir: %w", err)
		}
		logIfNotJSON("  ✅ Storage directory created")

		// 2. Create config
		if err := config.InitConfig(); err != nil {
			// config might already exist, that's fine
			logIfNotJSON("  ⚠ Config: " + err.Error())
		} else {
			logIfNotJSON("  ✅ Config created at ~/.config/security-vault/vault.yaml")
		}

		// 3. Run Python init to create DB + master key
		venvPython := "./venv/bin/python"
		if _, err := os.Stat(venvPython); os.IsNotExist(err) {
			venvPython = "python3"
		}

		initScript := `
import sys
sys.path.insert(0, ".")
from sqlalchemy import create_engine, text
from models import Base
from repositories import KeyRepository
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "vault.db")
STORAGE_PATH = "./secure_storage"

engine = create_engine(f"sqlite:///{DB_PATH}", connect_args={"check_same_thread": False})
with engine.connect() as conn:
    conn.execute(text("PRAGMA journal_mode=WAL"))
    conn.execute(text("PRAGMA busy_timeout=5000"))
    conn.commit()

Base.metadata.create_all(engine)
print("  ✅ Database tables created")

kr = KeyRepository(db_url=f"sqlite:///{DB_PATH}", engine=engine)
try:
    kr.get_active_key()
    print("  ✅ Master key exists")
except:
    import os as _os
    kr.create_key_version(_os.urandom(32).hex())
    print("  ✅ Master key created")
`

		cmd_ := exec.Command(venvPython, "-c", initScript)
		cmd_.Dir = findProjectRoot()
		cmd_.Stdout = os.Stderr
		cmd_.Stderr = os.Stderr
		if err := cmd_.Run(); err != nil {
			return fmt.Errorf("python init failed: %w", err)
		}

		if jsonOut {
			printJSON(map[string]string{
				"status":  "ok",
				"storage": storageDir,
				"database": filepath.Join(findProjectRoot(), "vault.db"),
			})
		} else {
			fmt.Println("\n✅ Vault initialized successfully")
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(initCmd)
}
