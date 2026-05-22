package cli

import (
	"fmt"
	"os"

	"github.com/Hunther4/Security-Vault/internal/config"
	"github.com/spf13/cobra"
)

var (
	cfgFile string
	jsonOut bool
	cfg     *config.Config
	cfgErr  error
)

var rootCmd = &cobra.Command{
	Use:   "vault",
	Short: "Secure Vault - encrypted document management",
	Long:  ``,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func loadConfig(cmd *cobra.Command) error {
	if cfg != nil {
		return nil
	}
	cfg, cfgErr = config.Load(cfgFile)
	if cfgErr != nil {
		return cfgErr
	}
	if v, _ := cmd.Flags().GetString("api-url"); v != "" {
		cfg.APIURL = v
	}
	if v, _ := cmd.Flags().GetString("api-key"); v != "" {
		cfg.APIKey = v
	}
	return nil
}

const SubHelpTemplate = `{{with (or .Long .Short)}}{{.}}
{{end}}Usage:
  vault/{{.Name}}{{if .HasFlags}} [flags]{{end}}

{{if .HasFlags}}Flags:
{{.Flags.FlagUsages | trimTrailingWhitespaces}}{{end}}{{if .HasParent}}

Global Flags:
{{.Parent.PersistentFlags.FlagUsages | trimTrailingWhitespaces}}{{end}}
`

func init() {
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file path")
	rootCmd.PersistentFlags().String("api-url", "", "API server URL (env: VAULT_API_URL)")
	rootCmd.PersistentFlags().String("api-key", "", "API key (env: VAULT_API_KEY)")
	rootCmd.PersistentFlags().BoolVarP(&jsonOut, "json", "j", false, "output as JSON")
	rootCmd.CompletionOptions.DisableDefaultCmd = true

	rootCmd.SetHelpTemplate(`{{with (or .Long .Short)}}{{.}}
{{end}}Usage:
  vault/<command> [flags]

Available Commands:{{range .Commands}}{{if (or .IsAvailableCommand (eq .Name "help"))}}
  vault/{{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}

Flags:
{{.PersistentFlags.FlagUsages | trimTrailingWhitespaces}}

Use "vault/<command> --help" for more information about a command.
`)
}
