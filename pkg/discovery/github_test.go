package discovery

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/go-github/v62/github"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGitHubResolver_Handles(t *testing.T) {
	r := NewGitHubResolverUnauthenticated()
	assert.True(t, r.Handles("github:topic/vctm"))
	assert.True(t, r.Handles("github:topic/vctm?org=siros"))
	assert.False(t, r.Handles("git:https://example.com"))
	assert.False(t, r.Handles("file:///local"))
	assert.False(t, r.Handles("github:user/repo"))
}

func TestGitHubResolver_Resolve(t *testing.T) {
	// Set up mock GitHub API
	mux := http.NewServeMux()
	mux.HandleFunc("/search/repositories", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		assert.Contains(t, q, "topic:vctm")
		assert.Contains(t, q, "org:testorg")

		url1 := "https://github.com/testorg/repo1.git"
		url2 := "https://github.com/testorg/repo2.git"
		result := github.RepositoriesSearchResult{
			Total: github.Int(2),
			Repositories: []*github.Repository{
				{CloneURL: &url1},
				{CloneURL: &url2},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(result)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client := github.NewClient(nil)
	client.BaseURL, _ = client.BaseURL.Parse(server.URL + "/")

	resolver := &GitHubResolver{Client: client}
	repos, err := resolver.Resolve("github:topic/vctm?org=testorg")
	require.NoError(t, err)
	assert.Equal(t, 2, len(repos))
	assert.Equal(t, "https://github.com/testorg/repo1.git", repos[0].URL)
	assert.Equal(t, "https://github.com/testorg/repo2.git", repos[1].URL)
}

func TestGitHubResolver_Resolve_EmptyTopic(t *testing.T) {
	resolver := NewGitHubResolverUnauthenticated()
	_, err := resolver.Resolve("github:topic/")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "empty topic")
}

func TestGitHubResolver_Resolve_NoOrg(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/search/repositories", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		assert.Contains(t, q, "topic:vctm")
		assert.NotContains(t, q, "org:")

		result := github.RepositoriesSearchResult{
			Total:        github.Int(0),
			Repositories: []*github.Repository{},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(result)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client := github.NewClient(nil)
	client.BaseURL, _ = client.BaseURL.Parse(server.URL + "/")

	resolver := &GitHubResolver{Client: client}
	repos, err := resolver.Resolve("github:topic/vctm")
	require.NoError(t, err)
	assert.Empty(t, repos)
}

func TestNewGitHubResolver(t *testing.T) {
	client := github.NewClient(nil)
	r := NewGitHubResolver(client)
	assert.NotNil(t, r)
	assert.Equal(t, client, r.Client)
}

func TestNewGitHubResolverWithToken(t *testing.T) {
	r := NewGitHubResolverWithToken("test-token")
	assert.NotNil(t, r)
	assert.NotNil(t, r.Client)
}
