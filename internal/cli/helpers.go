package cli

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/Hunther4/Security-Vault/internal/client"
	"github.com/spf13/cobra"
)

func printJSON(v any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(v)
}

func logIfNotJSON(msg string) {
	if !jsonOut {
		fmt.Fprintln(os.Stderr, msg)
	}
}

// Shell completion: list .go, .txt, .py, .yaml, .md, .json files
func completeFiles(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	return []string{"go", "txt", "py", "yaml", "md", "json"}, cobra.ShellCompDirectiveFilterFileExt
}

// Shell completion: list document IDs from the API
func completeDocumentIDs(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	if cfg == nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	c := client.New(cfg.APIURL, cfg.APIKey)
	docs, err := c.List()
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	ids := make([]string, 0, len(docs))
	for _, d := range docs {
		ids = append(ids, d.ID+"\t"+d.OriginalFilename)
	}
	return ids, cobra.ShellCompDirectiveNoFileComp
}
