package cmd

import (
	"fmt"
	"os"
	"os/exec"
)

// execGit runs a git command and returns any error.
func execGit(args ...string) error {
	cmd := exec.Command("git", args...)
	cmd.Stdout = os.Stderr // log git output to stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("git %v: %w", args, err)
	}
	return nil
}
