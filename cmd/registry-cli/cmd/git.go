package cmd

import (
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"strings"
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

// lastCommitTime returns the committer date (RFC 3339) of the most recent
// commit that touched any of relPaths within repoDir, or "" if the
// directory has no git history for those paths (e.g. a local file://
// source with no .git, or a shallow clone that never fetched the commit).
func lastCommitTime(repoDir string, relPaths []string) string {
	if len(relPaths) == 0 {
		return ""
	}
	args := append([]string{"-C", repoDir, "log", "-1", "--format=%cI", "--"}, relPaths...)
	out, err := exec.Command("git", args...).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
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
