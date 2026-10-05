package logship

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
)

// PermanentError marks a failure that retrying cannot fix.
//
// This distinction is not cosmetic. The shipper deliberately refuses to
// advance its bookmark past a failed batch, which is right for a network
// outage and catastrophic for a batch the server will never accept: that one
// batch would be resent every poll forever and every record behind it would
// never ship. Naming the difference is what keeps a single bad batch from
// silently stopping collection on that machine.
type PermanentError struct {
	Status int
	Body   string
}

func (e *PermanentError) Error() string {
	return fmt.Sprintf("server rejected the batch with %d: %s", e.Status, e.Body)
}

// HTTPUploader posts batches to the backend.
//
// Logs go over HTTPS rather than the agent's gRPC stream on purpose: that
// stream carries interactive screen data for remote control, and a few
// megabytes of log backlog sharing it would stall somebody's live session.
type HTTPUploader struct {
	// Client should be the agent's pinned-CA client, so log upload trusts
	// exactly what the rest of the agent's backend calls trust.
	Client *http.Client

	// Endpoint is the full URL of the backend's log intake.
	Endpoint string

	// Token authenticates the agent, as a bearer token.
	Token string

	// AgentID tells the backend which machine the batch belongs to; the
	// backend uses it to resolve the organisation, group and user the archive
	// path is built from.
	AgentID string
}

// NewHTTPUploader builds an uploader for a backend host.
func NewHTTPUploader(client *http.Client, host, token, agentID string) *HTTPUploader {
	return &HTTPUploader{
		Client:   client,
		Endpoint: strings.TrimSuffix(host, "/") + "/agent/logs",
		Token:    token,
		AgentID:  agentID,
	}
}

// Upload sends one gzipped NDJSON batch.
func (u *HTTPUploader) Upload(ctx context.Context, gzipped []byte, records int) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.Endpoint, bytes.NewReader(gzipped))
	if err != nil {
		return fmt.Errorf("building the log upload request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-ndjson")
	req.Header.Set("Content-Encoding", "gzip")
	req.Header.Set("Authorization", "Bearer "+u.Token)
	req.Header.Set("X-Agent-ID", u.AgentID)
	req.Header.Set("X-Record-Count", strconv.Itoa(records))
	req.ContentLength = int64(len(gzipped))

	client := u.Client
	if client == nil {
		client = http.DefaultClient
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("uploading logs: %w", err)
	}
	defer func() {
		// Drain before closing so the connection can be reused; at one upload
		// every thirty seconds, leaking a connection per batch adds up.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
		_ = resp.Body.Close()
	}()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<10))
	detail := truncate(strings.TrimSpace(string(body)), 256)

	if isPermanentStatus(resp.StatusCode) {
		return &PermanentError{Status: resp.StatusCode, Body: detail}
	}
	return fmt.Errorf("log upload failed with %d: %s", resp.StatusCode, detail)
}

// isPermanentStatus reports whether a status means "this batch will never be
// accepted" rather than "try again later".
//
// 408 and 429 are 4xx but explicitly ask for a retry, and 401/403 are
// excluded because they usually mean a token that is about to be renewed —
// dropping logs over a transient auth gap would lose exactly the records from
// the window somebody is most likely to ask about.
func isPermanentStatus(code int) bool {
	switch code {
	case http.StatusRequestTimeout, http.StatusTooManyRequests,
		http.StatusUnauthorized, http.StatusForbidden:
		return false
	}
	return code >= 400 && code < 500
}
