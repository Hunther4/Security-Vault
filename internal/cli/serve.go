package cli

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/spf13/cobra"
)

var (
	serveHost   string
	servePort   int
	serveReload bool
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the Security-Vault API server",
	RunE: func(cmd *cobra.Command, args []string) error {
		uvicornArgs := []string{
			"-m", "uvicorn", "api:app",
			"--host", serveHost,
			"--port", fmt.Sprintf("%d", servePort),
		}
		if serveReload {
			uvicornArgs = append(uvicornArgs, "--reload")
		}

		venvPython := "./venv/bin/python"
		if _, err := os.Stat(venvPython); os.IsNotExist(err) {
			venvPython = "python3"
		}

		pythonCmd := exec.Command(venvPython, uvicornArgs...)
		pythonCmd.Stdout = os.Stdout
		pythonCmd.Stderr = os.Stderr
		pythonCmd.Dir = findProjectRoot()

		fmt.Printf("🔐 Starting Security-Vault API on %s:%d\n", serveHost, servePort)
		return pythonCmd.Run()
	},
}

func init() {
	serveCmd.Flags().StringVarP(&serveHost, "host", "H", "0.0.0.0", "API server host")
	serveCmd.Flags().IntVarP(&servePort, "port", "p", 8000, "API server port")
	serveCmd.Flags().BoolVarP(&serveReload, "reload", "r", false, "Auto-reload on code changes (dev mode)")
	serveCmd.SetHelpTemplate(SubHelpTemplate)
	rootCmd.AddCommand(serveCmd)
}

func findProjectRoot() string {
	dir, _ := os.Getwd()
	for i := 0; i < 5; i++ {
		if _, err := os.Stat(dir + "/api.py"); err == nil {
			return dir
		}
		if _, err := os.Stat(dir + "/go.mod"); err == nil {
			return dir
		}
		parent := dir + "/.."
		if parent == dir {
			break
		}
		dir = parent
	}
	wd, _ := os.Getwd()
	return wd
}
