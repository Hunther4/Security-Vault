package cli

import (
	"fmt"

	"github.com/Hunther4/Security-Vault/internal/client"
	"github.com/spf13/cobra"
)

var rotateCmd = &cobra.Command{
	Use:   "rotate",
	Short: "Rotate the master encryption key",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := loadConfig(cmd); err != nil {
			return err
		}
		logIfNotJSON("🔄 Rotating key...")
		c := client.New(cfg.APIURL, cfg.APIKey)
		resp, err := c.Rotate()
		if err != nil {
			return err
		}

		if jsonOut {
			printJSON(resp)
		} else {
			fmt.Printf("✅ Key rotated. New version: %s\n", resp.KeyID)
		}
		return nil
	},
}

func init() {
	rotateCmd.SetHelpTemplate(SubHelpTemplate)
	rootCmd.AddCommand(rotateCmd)
}
