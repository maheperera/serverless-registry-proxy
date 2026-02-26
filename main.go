/*
Copyright 2020 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	ctxKeyOriginalHost = myContextKey("original-host")
)

var (
	re    = regexp.MustCompile(`^/v2/`)
	realm = regexp.MustCompile(`realm="(.*?)"`)
)

type myContextKey string

type registryConfig struct {
	host       string
	repoPrefix string
}

func main() {
	host := os.Getenv("HOST")

	port := os.Getenv("PORT")
	if port == "" {
		log.Fatal("PORT environment variable not specified")
	}
	browserRedirects := os.Getenv("DISABLE_BROWSER_REDIRECTS") == ""
	bypassGARBlobs := os.Getenv("DISABLE_GAR_BLOB_BYPASS") == ""

	registryHost := os.Getenv("REGISTRY_HOST")
	if registryHost == "" {
		log.Fatal("REGISTRY_HOST environment variable not specified (example: gcr.io)")
	}
	repoPrefix := os.Getenv("REPO_PREFIX")
	if repoPrefix == "" {
		log.Fatal("REPO_PREFIX environment variable not specified")
	}

	reg := registryConfig{
		host:       registryHost,
		repoPrefix: repoPrefix,
	}

	tokenEndpoint, err := discoverTokenService(reg.host)
	if err != nil {
		log.Fatalf("target registry's token endpoint could not be discovered: %+v", err)
	}
	log.Printf("discovered token endpoint for backend registry: %s", tokenEndpoint)

	var auth authenticator
	if basic := os.Getenv("AUTH_HEADER"); basic != "" {
		auth = authHeader(basic)
	} else if gcpKey := os.Getenv("GOOGLE_APPLICATION_CREDENTIALS"); gcpKey != "" {
		b, err := ioutil.ReadFile(gcpKey)
		if err != nil {
			log.Fatalf("could not read key file from %s: %+v", gcpKey, err)
		}
		log.Printf("using specified service account json key to authenticate proxied requests")
		auth = authHeader("Basic " + base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("_json_key:%s", string(b)))))
	} else if os.Getenv("USE_GCE_METADATA_SERVER") != "" {
		auth = &gceMetadataAuthenticator{}
	}

	mux := http.NewServeMux()
	if browserRedirects {
		mux.Handle("/", browserRedirectHandler(reg))
	}
	if tokenEndpoint != "" {
		mux.Handle("/_token", tokenProxyHandler(tokenEndpoint, repoPrefix))
	}
	mux.Handle("/v2/", registryAPIProxy(reg, auth, bypassGARBlobs))
	if !bypassGARBlobs {
		mux.Handle("/artifacts-downloads/", artifactRegistryBlobProxy(reg))
	}

	addr := fmt.Sprintf("%s:%s", host, port)
	handler := captureHostHeader(mux)
	log.Printf("starting to listen on %s", addr)
	if cert, key := os.Getenv("TLS_CERT"), os.Getenv("TLS_KEY"); cert != "" && key != "" {
		err = http.ListenAndServeTLS(addr, cert, key, handler)
	} else {
		err = http.ListenAndServe(addr, handler)
	}
	if err != http.ErrServerClosed {
		log.Fatalf("listen error: %+v", err)
	}

	log.Printf("server shutdown successfully")
}

func discoverTokenService(registryHost string) (string, error) {
	url := fmt.Sprintf("https://%s/v2/", registryHost)
	resp, err := http.Get(url)
	if err != nil {
		return "", fmt.Errorf("failed to query the registry host %s: %+v", registryHost, err)
	}
	hdr := resp.Header.Get("www-authenticate")
	if hdr == "" {
		return "", fmt.Errorf("www-authenticate header not returned from %s, cannot locate token endpoint", url)
	}
	matches := realm.FindStringSubmatch(hdr)
	if len(matches) == 0 {
		return "", fmt.Errorf("cannot locate 'realm' in %s response header www-authenticate: %s", url, hdr)
	}
	return matches[1], nil
}

// captureHostHeader is a middleware to capture Host header in a context key.
func captureHostHeader(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		ctx := context.WithValue(req.Context(), ctxKeyOriginalHost, req.Host)
		req = req.WithContext(ctx)
		next.ServeHTTP(rw, req.WithContext(ctx))
	})
}

// tokenProxyHandler proxies the token requests to the specified token service.
// It adjusts the ?scope= parameter in the query from "repository:foo:..." to
// "repository:repoPrefix/foo:.." and reverse proxies the query to the specified
// tokenEndpoint.
func tokenProxyHandler(tokenEndpoint, repoPrefix string) http.HandlerFunc {
	return (&httputil.ReverseProxy{
		FlushInterval: -1,
		Director: func(r *http.Request) {
			orig := r.URL.String()

			q := r.URL.Query()
			scope := q.Get("scope")
			if scope == "" {
				return
			}
			newScope := strings.Replace(scope, "repository:", fmt.Sprintf("repository:%s/", repoPrefix), 1)
			q.Set("scope", newScope)
			u, _ := url.Parse(tokenEndpoint)
			u.RawQuery = q.Encode()
			r.URL = u
			log.Printf("tokenProxyHandler: rewrote url:%s into:%s", orig, r.URL)
			r.Host = u.Host
		},
	}).ServeHTTP
}

// browserRedirectHandler redirects a request like example.com/my-image to
// REGISTRY_HOST/my-image, which shows a public UI for browsing the registry.
// This works only on registries that support a web UI when the image name is
// entered into the browser, like GCR (gcr.io/google-containers/busybox).
func browserRedirectHandler(cfg registryConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		url := fmt.Sprintf("https://%s/%s%s", cfg.host, cfg.repoPrefix, r.RequestURI)
		http.Redirect(w, r, url, http.StatusTemporaryRedirect)
	}
}

// registryAPIProxy returns a reverse proxy to the specified registry.
func registryAPIProxy(cfg registryConfig, auth authenticator, bypassGARBlobs bool) http.HandlerFunc {
	return (&httputil.ReverseProxy{
		FlushInterval: -1,
		Director:      rewriteRegistryV2URL(cfg),
		Transport: &registryRoundtripper{
			auth:           auth,
			bypassGARBlobs: bypassGARBlobs,
		},
	}).ServeHTTP
}

// rewriteRegistryV2URL rewrites request.URL like /v2/* that come into the server
// into https://[GCR_HOST]/v2/[PROJECT_ID]/*. It leaves /v2/ as is.
func rewriteRegistryV2URL(c registryConfig) func(*http.Request) {
	return func(req *http.Request) {
		u := req.URL.String()
		req.Host = c.host
		req.URL.Scheme = "https"
		req.URL.Host = c.host
		if req.URL.Path != "/v2/" {
			req.URL.Path = re.ReplaceAllString(req.URL.Path, fmt.Sprintf("/v2/%s/", c.repoPrefix))
		}
		log.Printf("rewrote url: %s into %s", u, req.URL)
	}
}

func artifactRegistryBlobProxy(cfg registryConfig) http.HandlerFunc {
	return (&httputil.ReverseProxy{
		FlushInterval: -1,
		Director:      rewriteArtifactRegistryBlobURL(cfg),
		Transport:     &followRedirectTransport{wrapped: http.DefaultTransport},
	}).ServeHTTP
}

// followRedirectTransport follows redirects (e.g. GAR → GCS signed URL) so
// that the short-lived signed URL is never exposed to the Docker client.
// Without this, Docker receives the signed URL directly and may try to resume
// a partial download after the URL has expired, causing connection resets.
type followRedirectTransport struct {
	wrapped http.RoundTripper
}

func (t *followRedirectTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	client := &http.Client{
		Transport: t.wrapped,
		CheckRedirect: func(newReq *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("too many redirects")
			}
			// Preserve Range header across redirects so partial/resumed
			// downloads work correctly against the final GCS endpoint.
			if rangeHdr := via[0].Header.Get("Range"); rangeHdr != "" {
				newReq.Header.Set("Range", rangeHdr)
			}
			return nil
		},
	}
	newReq, err := http.NewRequestWithContext(req.Context(), req.Method, req.URL.String(), req.Body)
	if err != nil {
		return nil, err
	}
	newReq.Header = req.Header.Clone()
	return client.Do(newReq)
}

func rewriteArtifactRegistryBlobURL(c registryConfig) func(*http.Request) {
	return func(req *http.Request) {
		u := req.URL.String()
		req.Host = c.host
		req.URL.Scheme = "https"
		req.URL.Host = c.host
		log.Printf("rewrote blob url: %s into %s", u, req.URL)
	}
}

type registryRoundtripper struct {
	auth           authenticator
	bypassGARBlobs bool
}

func (rrt *registryRoundtripper) RoundTrip(req *http.Request) (*http.Response, error) {
	log.Printf("request received. url=%s", req.URL)

	if rrt.auth != nil {
		req.Header.Set("Authorization", rrt.auth.AuthHeader())
	}

	origHost := req.Context().Value(ctxKeyOriginalHost).(string)
	if ua := req.Header.Get("user-agent"); ua != "" {
		req.Header.Set("user-agent", "gcr-proxy/0.1 customDomain/"+origHost+" "+ua)
	}

	resp, err := http.DefaultTransport.RoundTrip(req)
	if err == nil {
		log.Printf("request completed (status=%d) url=%s", resp.StatusCode, req.URL)
	} else {
		log.Printf("request failed with error: %+v", err)
		return nil, err
	}

	if rrt.bypassGARBlobs {
		// Google Artifact Registry sends a "location: /artifacts-downloads/..." URL
		// to download blobs. We don't want these routed to the proxy itself.
		if locHdr := resp.Header.Get("location"); req.Method == http.MethodGet &&
			resp.StatusCode == http.StatusFound && strings.HasPrefix(locHdr, "/") {
			resp.Header.Set("location", req.URL.Scheme+"://"+req.URL.Host+locHdr)
		}
	}

	updateTokenEndpoint(resp, origHost)
	return resp, nil
}

// updateTokenEndpoint modifies the response header like:
//
//	Www-Authenticate: Bearer realm="https://auth.docker.io/token",service="registry.docker.io"
//
// to point to the https://host/token endpoint to force using local token
// endpoint proxy.
func updateTokenEndpoint(resp *http.Response, host string) {
	v := resp.Header.Get("www-authenticate")
	if v == "" {
		return
	}
	cur := fmt.Sprintf("https://%s/_token", host)
	resp.Header.Set("www-authenticate", realm.ReplaceAllString(v, fmt.Sprintf(`realm="%s"`, cur)))
}

type authenticator interface {
	AuthHeader() string
}

type authHeader string

func (b authHeader) AuthHeader() string { return string(b) }

type gceMetadataAuthenticator struct {
	accessToken string
	tokenType   string
	expires     time.Time
	mu          sync.Mutex
}

func (g *gceMetadataAuthenticator) AuthHeader() string {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.accessToken != "" && time.Now().Before(g.expires) {
		return fmt.Sprintf("%s %s", g.tokenType, g.accessToken)
	}

	log.Printf("fetching new token from GCE metadata server")

	// Fetch a new token from the GCE metadata server
	const metadataURL = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
	req, err := http.NewRequest("GET", metadataURL, nil)
	if err != nil {
		log.Printf("failed to create request for metadata server: %+v", err)
		return ""
	}
	req.Header.Set("Metadata-Flavor", "Google")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Printf("failed to fetch token from metadata server: %+v", err)
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("unexpected status code from metadata server: %d", resp.StatusCode)
		return ""
	}

	var tokenResponse struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
		log.Printf("failed to decode token response: %+v", err)
		return ""
	}

	// Refresh a minute before expiration
	g.expires = time.Now().Add(time.Duration(tokenResponse.ExpiresIn) * time.Second).Add(-1 * time.Minute)
	g.accessToken = tokenResponse.AccessToken
	g.tokenType = tokenResponse.TokenType
	return fmt.Sprintf("%s %s", g.tokenType, g.accessToken)
}
