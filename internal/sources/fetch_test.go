package sources

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestFetchSendsConditionalHeaders(t *testing.T) {
	var gotETag, gotSince, gotUA string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotETag, gotSince, gotUA = r.Header.Get("If-None-Match"), r.Header.Get("If-Modified-Since"), r.UserAgent()
		w.WriteHeader(http.StatusNotModified)
	}))
	defer srv.Close()
	prev := FetchState{ETag: `"a"`, LastModified: "Tue, 17 Nov 2026 10:00:00 GMT"}
	res, err := Fetch(context.Background(), srv.Client(), srv.URL, prev)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if !res.NotModified {
		t.Error("NotModified = false, want true")
	}
	if gotETag != `"a"` || gotSince != prev.LastModified {
		t.Errorf("headers: If-None-Match=%q If-Modified-Since=%q", gotETag, gotSince)
	}
	if !strings.HasPrefix(gotUA, "bot-verify/") {
		t.Errorf("User-Agent = %q", gotUA)
	}
	if res.State != prev {
		t.Errorf("State = %+v, want previous state kept on 304", res.State)
	}
}

func TestFetchReturnsBodyAndState(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"b"`)
		w.Header().Set("Last-Modified", "Tue, 17 Nov 2026 11:00:00 GMT")
		w.Write([]byte("192.0.2.1\n"))
	}))
	defer srv.Close()
	res, err := Fetch(context.Background(), srv.Client(), srv.URL, FetchState{})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if string(res.Body) != "192.0.2.1\n" || res.State.ETag != `"b"` || res.State.LastModified == "" || res.NotModified {
		t.Errorf("got %+v", res)
	}
}

func TestFetchRejectsNon200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	if _, err := Fetch(context.Background(), srv.Client(), srv.URL, FetchState{}); err == nil {
		t.Error("no error for status 500")
	}
}

func TestFetchRejectsOversize(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(make([]byte, MaxBodyBytes+1))
	}))
	defer srv.Close()
	if _, err := Fetch(context.Background(), srv.Client(), srv.URL, FetchState{}); err == nil {
		t.Error("no error for oversize body")
	}
}
