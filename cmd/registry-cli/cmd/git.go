package cmd

import (
	"fmt"
	"net/url"
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

// injectToken injects a token into an HTTPS git URL for authentication.
// For non-HTTPS URLs or empty tokens, the URL is returned unchanged.
func injectToken(cloneURL, token string) string {
	if token == "" {
		return cloneURL
	}
	u, err := url.Parse(cloneURL)
	if err != nil || u.Scheme != "https" {
		return cloneURL
	}
	u.User = url.UserPassword("x-access-token", token)
	return u.String()
}
