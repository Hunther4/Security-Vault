package cli

import (
	"fmt"

	"github.com/Hunther4/Security-Vault/internal/client"
	"github.com/spf13/cobra"
)

var decryptCmd = &cobra.Command{
	Use:   "decrypt <document-id>",
	Short: "Download and decrypt a document from the vault",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := loadConfig(cmd); err != nil {
			return err
		}
		logIfNotJSON("🔓 Decrypting...")
		actor, _ := cmd.Flags().GetString("actor")
		outputDir, _ := cmd.Flags().GetString("output")
		docID := args[0]

		if outputDir == "" {
			outputDir = cfg.OutputDir
		}

		c := client.New(cfg.APIURL, cfg.APIKey)
		outPath, err := c.Download(docID, outputDir, actor)
		if err != nil {
			return fmt.Errorf("download failed: %w", err)
		}

		if jsonOut {
			printJSON(map[string]string{"file": outPath, "document_id": docID})
		} else {
			fmt.Printf("✅ Decrypted to: %s\n", outPath)
		}
		return nil
	},
	ValidArgsFunction: completeDocumentIDs,
}

func init() {
	decryptCmd.Flags().String("actor", "vault-cli", "Actor name for audit log")
	decryptCmd.Flags().StringP("output", "o", "", "Output directory (default: config output_dir)")
	decryptCmd.SetHelpTemplate(SubHelpTemplate)
	rootCmd.AddCommand(decryptCmd)
}
