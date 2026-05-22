package cli

import (
	"fmt"
	"os"

	"github.com/Hunther4/Security-Vault/internal/client"
	"github.com/spf13/cobra"
)

var encryptCmd = &cobra.Command{
	Use:   "encrypt <file>",
	Short: "Encrypt and upload a file to the vault",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := loadConfig(cmd); err != nil {
			return err
		}
		logIfNotJSON("🔐 Encrypting...")
		actor, _ := cmd.Flags().GetString("actor")
		filePath := args[0]

		if _, err := os.Stat(filePath); os.IsNotExist(err) {
			return fmt.Errorf("file not found: %s", filePath)
		}

		c := client.New(cfg.APIURL, cfg.APIKey)
		resp, err := c.Upload(filePath, actor)
		if err != nil {
			return fmt.Errorf("upload failed: %w", err)
		}

		if jsonOut {
			printJSON(resp)
		} else {
			fmt.Printf("✅ Encrypted: %s (ID: %s)\n", resp.Filename, resp.DocumentID)
		}
		return nil
	},
	ValidArgsFunction: completeFiles,
}

func init() {
	encryptCmd.Flags().String("actor", "vault-cli", "Actor name for audit log")
	encryptCmd.SetHelpTemplate(SubHelpTemplate)
	rootCmd.AddCommand(encryptCmd)
}
