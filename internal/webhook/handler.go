package webhook

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/yagihash/ghmint/pkg/logger"
	"github.com/yagihash/ghmint/pkg/signer"
)

const maxWebhookBodyBytes = 10 * 1024 * 1024

// Handler handles GitHub webhook events and validates Rego policy files via GitHub Checks API.
type Handler struct {
	webhookSecret string
	logger        logger.Logger
	gh            *githubClient
}

// NewHandler creates a Handler. appID and s are used to authenticate with the GitHub App.
func NewHandler(appID string, s signer.Signer, webhookSecret string, log logger.Logger) *Handler {
	return &Handler{
		webhookSecret: webhookSecret,
		logger:        log,
		gh:            newGithubClient(appID, s),
	}
}

type pullRequestPayload struct {
	Action      string `json:"action"`
	Number      int    `json:"number"`
	PullRequest struct {
		Head struct {
			SHA string `json:"sha"`
		} `json:"head"`
	} `json:"pull_request"`
	Repository struct {
		Name  string `json:"name"`
		Owner struct {
			Login string `json:"login"`
		} `json:"owner"`
	} `json:"repository"`
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxWebhookBodyBytes))
	if err != nil {
		http.Error(w, "failed to read body", http.StatusInternalServerError)
		return
	}

	if !h.verifySignature(body, r.Header.Get("X-Hub-Signature-256")) {
		http.Error(w, "invalid signature", http.StatusUnauthorized)
		return
	}

	if r.Header.Get("X-GitHub-Event") != "pull_request" {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	var payload pullRequestPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		http.Error(w, "invalid payload", http.StatusBadRequest)
		return
	}

	switch payload.Action {
	case "opened", "synchronize", "reopened":
	default:
		w.WriteHeader(http.StatusNoContent)
		return
	}

	w.WriteHeader(http.StatusAccepted)

	ctx := context.Background()
	log := h.logger.With(
		"owner", payload.Repository.Owner.Login,
		"repo", payload.Repository.Name,
		"pr", payload.Number,
	)
	go func() {
		if err := h.processValidation(ctx, log, payload); err != nil {
			log.ErrorContext(ctx, "webhook processing failed", "error", err)
		}
	}()
}

func (h *Handler) verifySignature(body []byte, sig string) bool {
	expected, ok := strings.CutPrefix(sig, "sha256=")
	if !ok {
		return false
	}
	mac := hmac.New(sha256.New, []byte(h.webhookSecret))
	mac.Write(body)
	got := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(expected), []byte(got))
}

func (h *Handler) processValidation(ctx context.Context, log logger.Logger, payload pullRequestPayload) error {
	owner := payload.Repository.Owner.Login
	repo := payload.Repository.Name
	prNumber := payload.Number
	headSHA := payload.PullRequest.Head.SHA

	// Policies in the ".github" repository are invoked with org scope;
	// all other repositories use org/repo scope where repositories must be undefined.
	isOrgRepo := repo != ".github"

	token, err := h.gh.tokenForOwner(ctx, owner)
	if err != nil {
		return fmt.Errorf("get installation token: %w", err)
	}

	files, err := h.gh.listPRFiles(ctx, token, owner, repo, prNumber)
	if err != nil {
		return fmt.Errorf("list pr files: %w", err)
	}
	if len(files) == 0 {
		log.DebugContext(ctx, "no rego policy files changed, skipping check run")
		return nil
	}

	checkRunID, err := h.gh.createCheckRun(ctx, token, owner, repo, headSHA)
	if err != nil {
		return fmt.Errorf("create check run: %w", err)
	}

	var allAnnotations []annotation
	for _, f := range files {
		content, err := h.gh.getFileContent(ctx, token, owner, repo, f, headSHA)
		if err != nil {
			log.WarnContext(ctx, "could not fetch rego file", "path", f, "error", err)
			allAnnotations = append(allAnnotations, annotation{
				Path:            f,
				StartLine:       1,
				EndLine:         1,
				AnnotationLevel: "failure",
				Message:         fmt.Sprintf("could not fetch file: %v", err),
			})
			continue
		}

		vr := validateRegoFile(f, content, isOrgRepo)
		for _, e := range vr.Errors {
			line := e.Line
			if line == 0 {
				line = 1
			}
			allAnnotations = append(allAnnotations, annotation{
				Path:            f,
				StartLine:       line,
				EndLine:         line,
				AnnotationLevel: "failure",
				Message:         e.Message,
			})
		}
		for _, w := range vr.Warnings {
			line := w.Line
			if line == 0 {
				line = 1
			}
			allAnnotations = append(allAnnotations, annotation{
				Path:            f,
				StartLine:       line,
				EndLine:         line,
				AnnotationLevel: "warning",
				Message:         w.Message,
			})
		}
	}

	errCount := 0
	for _, a := range allAnnotations {
		if a.AnnotationLevel == "failure" {
			errCount++
		}
	}

	conclusion := "success"
	summary := fmt.Sprintf("Validated %d policy file(s). No issues found.", len(files))
	if errCount > 0 {
		conclusion = "failure"
		summary = fmt.Sprintf("Validated %d policy file(s). Found %d error(s).", len(files), errCount)
	}

	if err := h.gh.updateCheckRun(ctx, token, owner, repo, checkRunID, conclusion, allAnnotations, summary); err != nil {
		return fmt.Errorf("update check run: %w", err)
	}

	log.InfoContext(ctx, "policy validation complete",
		"conclusion", conclusion,
		"files", len(files),
		"errors", errCount,
	)
	return nil
}
