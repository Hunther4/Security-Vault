package cli

import (
	"fmt"
	"os"


	"github.com/spf13/cobra"
)

var completionCmd = &cobra.Command{
	Use:   "completion <shell>",
	Short: "Generate shell completion scripts",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		shell := args[0]
		switch shell {
		case "bash":
			return generateBashCompletion(cmd)
		case "zsh":
			return generateZshCompletion(cmd)
		default:
			return fmt.Errorf("unsupported shell: %s (use bash or zsh)", shell)
		}
	},
}

func init() {
	rootCmd.AddCommand(completionCmd)
}

func generateBashCompletion(cmd *cobra.Command) error {
	out := os.Stdout

	// Custom bash completion with vault/<command> style
	fmt.Fprint(out, `# vault shell completion (bash)
# source this file: source <(vault completion bash)

_vault_completions() {
    local cur prev words cword
    _init_completion || return

    # Support vault/<command> syntax
    if [[ "$prev" == "vault" && "$cur" == */* ]]; then
        # vault/en<TAB> -> complete the subcommand
        local sub="${cur#*/}"
        COMPREPLY=($(compgen -W "$(vault __commands)" -- "$sub"))
        # Prefix with "vault/" to maintain the visual style
        COMPREPLY=("${COMPREPLY[@]/#/vault/}")
        return
    fi

    # Get the command name (after replacing vault/ with vault space)
    local cmd="${words[1]}"
    [[ "$cmd" == */* ]] && cmd="${cmd#*/}"
    
    # If we're on the first arg after vault
    if [[ $cword -eq 1 ]]; then
        COMPREPLY=($(compgen -W "$(vault __commands)" -- "$cur"))
        return
    fi

    # Delegate to cobra's built-in completion for flags and args
    COMP_WORDS=("vault" "$cmd" "${COMP_WORDS[@]:2}")
    COMP_CWORD=$((cword - 1))
    _vault_completion
}

# Register the completion for both "vault" and "vault/*" style
complete -F _vault_completions vault

# The __commands hidden command lists available subcommands
`)
	return nil
}

func generateZshCompletion(cmd *cobra.Command) error {
	out := os.Stdout

	fmt.Fprintf(out, `# vault shell completion (zsh)
# source this file: source <(vault completion zsh)

# Extract command names dynamically
__vault_commands() {
    vault __commands 2>/dev/null
}

# Main completion function
_vault() {
    local curcontext="$curcontext" state line
    typeset -A opt_args

    # Handle vault/<command> syntax
    if [[ $words[1] == */* ]]; then
        words[1]="vault"
        words[2]="${${words[2]}#*/}"
    fi

    _arguments \
        '(- : *)'{-h,--help}'[show help]' \
        '(- : *)'{-j,--json}'[output as JSON]' \
        '1: :->command' \
        '*: :->args'

    case $state in
        command)
            local -a commands
            commands=(${(f)"$(__vault_commands)"})
            _describe 'command' commands
            ;;
        args)
            # fall through to default completion
            _default
            ;;
    esac
}

compdef _vault vault
`)
	return nil
}

// __commands is a hidden command that lists subcommands for completion
var commandsCmd = &cobra.Command{
	Use:    "__commands",
	Short:  "hidden: list subcommands for completion",
	Hidden: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		for _, c := range rootCmd.Commands() {
			if c.IsAvailableCommand() && !c.Hidden {
				fmt.Println(c.Name())
			}
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(commandsCmd)
}
