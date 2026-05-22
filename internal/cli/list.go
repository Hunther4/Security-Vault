package cli

import (
	"fmt"

	"github.com/Hunther4/Security-Vault/internal/client"
	"github.com/spf13/cobra"
)

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List all documents in the vault",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := loadConfig(cmd); err != nil {
			return err
		}
		c := client.New(cfg.APIURL, cfg.APIKey)
		docs, err := c.List()
		if err != nil {
			return err
		}

		if jsonOut {
			printJSON(docs)
		} else {
			if len(docs) == 0 {
				fmt.Println("📂 No documents in vault")
				return nil
			}
			for _, d := range docs {
				fmt.Printf("  %s  %s (%dB)\n", d.ID[:8], d.OriginalFilename, d.SizeBytes)
			}
		}
		return nil
	},
}

func init() {
	listCmd.SetHelpTemplate(SubHelpTemplate)
	rootCmd.AddCommand(listCmd)
}
