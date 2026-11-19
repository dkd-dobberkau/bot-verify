package api

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"net/http"
)

// homePage tells people who open the domain what it is, and links the
// operator's Impressum and Datenschutz.
//
//go:embed home.html
var homePage []byte

// homeCSP allows the page's one inline style block by its hash and nothing
// else, so the page needs no looser policy than the API.
var homeCSP = func() string {
	start := bytes.Index(homePage, []byte("<style>")) + len("<style>")
	end := bytes.Index(homePage, []byte("</style>"))
	sum := sha256.Sum256(homePage[start:end])
	return baseCSP + "; style-src 'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
}()

// robotsTxt keeps crawlers off the API; the home page may be indexed.
const robotsTxt = "User-agent: *\nDisallow: /v1/\n"

func home(w http.ResponseWriter, _ *http.Request) {
	h := w.Header()
	h.Set("Content-Security-Policy", homeCSP)
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "public, max-age=3600")
	w.Write(homePage)
}

func robots(w http.ResponseWriter, _ *http.Request) {
	h := w.Header()
	h.Set("Content-Type", "text/plain; charset=utf-8")
	h.Set("Cache-Control", "public, max-age=86400")
	w.Write([]byte(robotsTxt))
}
