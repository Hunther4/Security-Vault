package cli

import (
	"fmt"
	"os"

	"github.com/Hunther4/Security-Vault/internal/config"
	"github.com/spf13/cobra"
)

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Manage CLI configuration",
}

var configInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Create default config file",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := config.InitConfig(); err != nil {
			return err
		}
		fmt.Println("✅ Config created at ~/.config/security-vault/vault.yaml")
		return nil
	},
}

var configShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show current config",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := loadConfig(cmd); err != nil {
			return err
		}
		if jsonOut {
			printJSON(cfg)
		} else {
			fmt.Fprintf(os.Stdout, "api_url:   %s\napi_key:   %s\noutput_dir: %s\n", cfg.APIURL, cfg.APIKey, cfg.OutputDir)
		}
		return nil
	},
}

func init() {
	configCmd.SetHelpTemplate(SubHelpTemplate)
	configInitCmd.SetHelpTemplate(SubHelpTemplate)
	configShowCmd.SetHelpTemplate(SubHelpTemplate)
	configCmd.AddCommand(configInitCmd, configShowCmd)
	rootCmd.AddCommand(configCmd)
}
