package sources

import (
	"context"
	"fmt"
	"io"
	"net/http"
)

// MaxBodyBytes caps a source body; the largest real list is well under 100 KiB.
const MaxBodyBytes = 5 << 20

// UserAgent identifies bot-verify to operators; main sets the version.
var UserAgent = "bot-verify/dev (+https://github.com/dkd-dobberkau/bot-verify)"

// FetchState is what a source told us last time, for conditional requests.
type FetchState struct {
	ETag         string
	LastModified string
}

// FetchResult is one fetch. On 304, Body is nil and State is the previous one.
type FetchResult struct {
	Body        []byte
	NotModified bool
	State       FetchState
}

// Fetch GETs a source with If-None-Match/If-Modified-Since from prev.
func Fetch(ctx context.Context, client *http.Client, url string, prev FetchState) (FetchResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return FetchResult{}, err
	}
	req.Header.Set("User-Agent", UserAgent)
	if prev.ETag != "" {
		req.Header.Set("If-None-Match", prev.ETag)
	}
	if prev.LastModified != "" {
		req.Header.Set("If-Modified-Since", prev.LastModified)
	}
	resp, err := client.Do(req)
	if err != nil {
		return FetchResult{}, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusNotModified:
		return FetchResult{NotModified: true, State: prev}, nil
	case http.StatusOK:
	default:
		return FetchResult{}, fmt.Errorf("status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxBodyBytes+1))
	if err != nil {
		return FetchResult{}, err
	}
	if len(body) > MaxBodyBytes {
		return FetchResult{}, fmt.Errorf("body larger than %d bytes", MaxBodyBytes)
	}
	return FetchResult{
		Body:  body,
		State: FetchState{ETag: resp.Header.Get("ETag"), LastModified: resp.Header.Get("Last-Modified")},
	}, nil
}
