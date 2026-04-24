package discovery

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/google/go-github/v62/github"
	"golang.org/x/oauth2"
)

// GitHubResolver resolves github:topic/<topic> meta-sources via the GitHub API.
type GitHubResolver struct {
	Client *github.Client
}

func NewGitHubResolver(client *github.Client) *GitHubResolver {
	return &GitHubResolver{Client: client}
}

// NewGitHubResolverWithToken creates a resolver authenticated with a personal access token.
func NewGitHubResolverWithToken(token string) *GitHubResolver {
	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token})
	tc := oauth2.NewClient(context.Background(), ts)
	return &GitHubResolver{Client: github.NewClient(tc)}
}

// NewGitHubResolverUnauthenticated creates an unauthenticated resolver (lower rate limits).
func NewGitHubResolverUnauthenticated() *GitHubResolver {
	return &GitHubResolver{Client: github.NewClient(nil)}
}

func (r *GitHubResolver) Handles(source string) bool {
	return strings.HasPrefix(source, "github:topic/")
}

func (r *GitHubResolver) Resolve(source string) ([]ResolvedRepo, error) {
	// Parse: github:topic/<topic>?org=<org>
	rest := strings.TrimPrefix(source, "github:topic/")
	topic, queryStr, _ := strings.Cut(rest, "?")
	if topic == "" {
		return nil, fmt.Errorf("empty topic in %q", source)
	}

	params, err := url.ParseQuery(queryStr)
	if err != nil {
		return nil, fmt.Errorf("parsing query in %q: %w", source, err)
	}
	org := params.Get("org")

	query := fmt.Sprintf("topic:%s", topic)
	if org != "" {
		query += fmt.Sprintf(" org:%s", org)
	}

	var repos []ResolvedRepo
	opts := &github.SearchOptions{
		ListOptions: github.ListOptions{PerPage: 100},
	}

	for {
		result, resp, err := r.Client.Search.Repositories(context.Background(), query, opts)
		if err != nil {
			return nil, fmt.Errorf("GitHub search for %q: %w", query, err)
		}
		for _, repo := range result.Repositories {
			repos = append(repos, ResolvedRepo{
				URL: repo.GetCloneURL(),
			})
		}
		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}

	return repos, nil
}
