package webhook

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

// redirectTransport rewrites the host of every request to the target server,
// matching the pattern used by the other packages' GitHub API test doubles.
type redirectTransport struct {
	target *url.URL
}

func (t *redirectTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.URL.Host = t.target.Host
	req.URL.Scheme = t.target.Scheme
	return http.DefaultTransport.RoundTrip(req)
}

func newTestGithubClient(t *testing.T, srv *httptest.Server) *githubClient {
	t.Helper()
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	c := newGithubClient(nil)
	c.httpClient = &http.Client{Transport: &redirectTransport{target: u}}
	return c
}

// prFile is a minimal stand-in for the GitHub pulls/files API response shape.
type prFile struct {
	Filename string `json:"filename"`
	Status   string `json:"status"`
}

func filesServer(t *testing.T, pages [][]prFile) *httptest.Server {
	t.Helper()
	var mux http.ServeMux
	mux.HandleFunc("/repos/org/repo/pulls/1/files", func(w http.ResponseWriter, r *http.Request) {
		page := 1
		if p := r.URL.Query().Get("page"); p != "" {
			fmt.Sscanf(p, "%d", &page)
		}
		w.Header().Set("Content-Type", "application/json")
		if page < 1 || page > len(pages) {
			json.NewEncoder(w).Encode([]prFile{})
			return
		}
		json.NewEncoder(w).Encode(pages[page-1])
	})
	srv := httptest.NewServer(&mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestListPRFiles_FiltersRemoved(t *testing.T) {
	srv := filesServer(t, [][]prFile{
		{
			{Filename: ".github/ghmint/a.rego", Status: "modified"},
			{Filename: ".github/ghmint/b.rego", Status: "removed"},
			{Filename: "README.md", Status: "modified"},
		},
	})
	c := newTestGithubClient(t, srv)

	got, err := c.listPRFiles(context.Background(), "tok", "org", "repo", 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 || got[0] != ".github/ghmint/a.rego" {
		t.Errorf("expected only the modified rego file, got %v", got)
	}
}

func TestListPRFiles_Paginates(t *testing.T) {
	page1 := make([]prFile, prFilesPerPage)
	for i := range page1 {
		page1[i] = prFile{Filename: fmt.Sprintf("file-%d.txt", i), Status: "modified"}
	}
	page2 := []prFile{{Filename: ".github/ghmint/late.rego", Status: "added"}}

	srv := filesServer(t, [][]prFile{page1, page2})
	c := newTestGithubClient(t, srv)

	got, err := c.listPRFiles(context.Background(), "tok", "org", "repo", 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 || got[0] != ".github/ghmint/late.rego" {
		t.Errorf("expected to find the rego file on page 2, got %v", got)
	}
}
