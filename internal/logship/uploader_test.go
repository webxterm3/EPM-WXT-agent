package logship

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestUploaderSendsTheBatchTheBackendExpects(t *testing.T) {
	var (
		gotAuth, gotEncoding, gotType, gotAgent, gotCount string
		gotBody                                           []byte
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotEncoding = r.Header.Get("Content-Encoding")
		gotType = r.Header.Get("Content-Type")
		gotAgent = r.Header.Get("X-Agent-ID")
		gotCount = r.Header.Get("X-Record-Count")
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	up := NewHTTPUploader(srv.Client(), srv.URL, "tok-123", "agent-7")
	payload, err := encodeBatch(makeRecords(3))
	if err != nil {
		t.Fatal(err)
	}
	if err := up.Upload(context.Background(), payload, 3); err != nil {
		t.Fatalf("Upload: %v", err)
	}

	if gotAuth != "Bearer tok-123" {
		t.Errorf("Authorization = %q", gotAuth)
	}
	if gotAgent != "agent-7" {
		t.Errorf("X-Agent-ID = %q — the backend cannot place the archive without it", gotAgent)
	}
	if gotCount != "3" {
		t.Errorf("X-Record-Count = %q", gotCount)
	}
	if gotType != "application/x-ndjson" {
		t.Errorf("Content-Type = %q", gotType)
	}
	// The body must arrive still compressed: declaring gzip and sending plain
	// bytes would make the backend store unreadable objects.
	if gotEncoding != "gzip" {
		t.Errorf("Content-Encoding = %q", gotEncoding)
	}
	if _, err := gzip.NewReader(bytes.NewReader(gotBody)); err != nil {
		t.Errorf("the body was not valid gzip: %v", err)
	}
}

func TestUploaderPostsToTheLogEndpoint(t *testing.T) {
	var path string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
	}))
	defer srv.Close()

	// A trailing slash on the configured host must not produce "//agent/logs",
	// which some gateways route differently or reject outright.
	up := NewHTTPUploader(srv.Client(), srv.URL+"/", "t", "a")
	if err := up.Upload(context.Background(), []byte("x"), 1); err != nil {
		t.Fatal(err)
	}
	if path != "/agent/logs" {
		t.Errorf("posted to %q, want /agent/logs", path)
	}
}

// A 5xx is the server having a bad day: the batch must be retried, so the
// bookmark stays put.
func TestServerErrorIsRetryable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "database down", http.StatusBadGateway)
	}))
	defer srv.Close()

	err := NewHTTPUploader(srv.Client(), srv.URL, "t", "a").
		Upload(context.Background(), []byte("x"), 1)
	if err == nil {
		t.Fatal("a 502 was reported as success")
	}
	var permanent *PermanentError
	if errors.As(err, &permanent) {
		t.Error("a 502 was classed as permanent; the batch would be thrown away over a transient outage")
	}
}

// A 400 will never succeed. Retrying it forever would wedge the source and
// block every record behind it, so it has to be recognisable as final.
func TestBadRequestIsPermanent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "malformed batch", http.StatusBadRequest)
	}))
	defer srv.Close()

	err := NewHTTPUploader(srv.Client(), srv.URL, "t", "a").
		Upload(context.Background(), []byte("x"), 1)

	var permanent *PermanentError
	if !errors.As(err, &permanent) {
		t.Fatalf("a 400 was not classed as permanent: %v", err)
	}
	if permanent.Status != 400 {
		t.Errorf("Status = %d", permanent.Status)
	}
}

// Auth failures look permanent but usually are not: the agent renews its token
// on a schedule. Dropping logs during that window would lose exactly the
// records from the period somebody is most likely to be asking about.
func TestAuthFailuresAreRetriedNotDropped(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden,
		http.StatusRequestTimeout, http.StatusTooManyRequests} {
		if isPermanentStatus(status) {
			t.Errorf("status %d was classed as permanent", status)
		}
	}
	for _, status := range []int{http.StatusBadRequest, http.StatusRequestEntityTooLarge,
		http.StatusUnsupportedMediaType, http.StatusNotFound} {
		if !isPermanentStatus(status) {
			t.Errorf("status %d was not classed as permanent", status)
		}
	}
}

// The counterpart in the shipper: a rejected batch must be stepped over so the
// records behind it can still ship.
func TestRejectedBatchDoesNotBlockTheOnesBehindIt(t *testing.T) {
	src := &fakeSource{name: "test", records: makeRecords(30)}
	up := &rejectFirstUploader{}
	s := newShipper(t, src, up, nil)

	s.poll(context.Background())

	if up.accepted == 0 {
		t.Fatal("nothing shipped after one batch was rejected — the source is wedged")
	}
	if up.accepted != 20 {
		t.Errorf("accepted %d records, want the 20 behind the rejected batch", up.accepted)
	}
}

// rejectFirstUploader permanently rejects the first batch and accepts the rest.
type rejectFirstUploader struct {
	calls    int
	accepted int
}

func (u *rejectFirstUploader) Upload(_ context.Context, _ []byte, records int) error {
	u.calls++
	if u.calls == 1 {
		return &PermanentError{Status: 400, Body: "malformed"}
	}
	u.accepted += records
	return nil
}
