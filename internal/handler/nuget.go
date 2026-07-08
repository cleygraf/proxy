package handler

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/git-pkgs/purl"
)

const (
	nugetUpstream = "https://api.nuget.org"
)

// NuGetHandler handles NuGet V3 API protocol requests.
type NuGetHandler struct {
	proxy       *Proxy
	upstreamURL string
	proxyURL    string
}

// NewNuGetHandler creates a new NuGet protocol handler.
func NewNuGetHandler(proxy *Proxy, proxyURL, upstreamURL string) *NuGetHandler {
	if strings.TrimSpace(upstreamURL) == "" {
		upstreamURL = nugetUpstream
	}
	return &NuGetHandler{
		proxy:       proxy,
		upstreamURL: strings.TrimSuffix(upstreamURL, "/"),
		proxyURL:    strings.TrimSuffix(proxyURL, "/"),
	}
}

// applyUpstreamAuth adds configured upstream auth (e.g. Sonatype Firewall basic
// auth) to a direct upstream request. The cached fetch paths already do this via
// the auth-aware fetcher; the handler's direct HTTPClient.Do calls do not.
func (h *NuGetHandler) applyUpstreamAuth(req *http.Request, url string) {
	if h.proxy.AuthForURL == nil {
		return
	}
	if name, value := h.proxy.AuthForURL(url); name != "" {
		req.Header.Set(name, value)
	}
}

// Routes returns the HTTP handler for NuGet requests.
func (h *NuGetHandler) Routes() http.Handler {
	mux := http.NewServeMux()

	// V3 API service index
	mux.HandleFunc("GET /v3/index.json", h.handleServiceIndex)

	// Package content (downloads)
	mux.HandleFunc("GET /v3-flatcontainer/{id}/{version}/{filename}", h.handleDownload)
	mux.HandleFunc("GET /v3-flatcontainer/{id}/index.json", h.proxyUpstream)

	// Registration (package metadata) - use prefix matching since {version}.json isn't allowed
	mux.HandleFunc("GET /v3/registration5-gz-semver2/", h.handleRegistration)

	// Search
	mux.HandleFunc("GET /query", h.proxyUpstream)

	// Autocomplete
	mux.HandleFunc("GET /autocomplete", h.proxyUpstream)

	return mux
}

// handleServiceIndex serves the NuGet V3 service index with rewritten URLs.
func (h *NuGetHandler) handleServiceIndex(w http.ResponseWriter, r *http.Request) {
	h.proxy.Logger.Info("nuget service index request")

	upstreamURL := h.upstreamURL + "/v3/index.json"

	body, _, err := h.proxy.FetchOrCacheMetadata(r.Context(), "nuget", "_service_index", upstreamURL)
	if err != nil {
		if errors.Is(err, ErrUpstreamNotFound) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		h.proxy.Logger.Error("upstream request failed", "error", err)
		http.Error(w, "upstream request failed", http.StatusBadGateway)
		return
	}

	rewritten, err := h.rewriteServiceIndex(body)
	if err != nil {
		h.proxy.Logger.Warn("failed to rewrite service index, proxying original", "error", err)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(rewritten)
}

// rewriteServiceIndex rewrites service URLs in the index to point at this proxy.
func (h *NuGetHandler) rewriteServiceIndex(body []byte) ([]byte, error) {
	var index map[string]any
	if err := json.Unmarshal(body, &index); err != nil {
		return nil, err
	}

	resources, ok := index["resources"].([]any)
	if !ok {
		return body, nil
	}

	customUpstream := h.upstreamURL != nugetUpstream
	kept := resources[:0]
	for _, res := range resources {
		rmap, ok := res.(map[string]any)
		if !ok {
			kept = append(kept, res)
			continue
		}

		id, _ := rmap["@id"].(string)
		rtype, _ := rmap["@type"].(string)

		// We do not re-serve repository signatures for a custom upstream; drop the
		// resource so the client does not require repository-signed packages.
		if customUpstream && strings.HasPrefix(rtype, "RepositorySignatures") {
			continue
		}

		// Rewrite URLs for services we proxy. For a custom upstream (e.g. Sonatype
		// Firewall) also rewrite any other service under the upstream base, so the
		// client never talks to the upstream directly.
		if id != "" && (h.shouldRewriteService(rtype) ||
			(customUpstream && strings.HasPrefix(id, h.upstreamURL+"/"))) {
			rmap["@id"] = h.rewriteNuGetURL(id)
		}
		kept = append(kept, res)
	}
	index["resources"] = kept

	return json.Marshal(index)
}

// shouldRewriteService returns true if the service type should be rewritten.
func (h *NuGetHandler) shouldRewriteService(serviceType string) bool {
	// Rewrite package content and registration services
	rewriteTypes := []string{
		"PackageBaseAddress/3.0.0",
		"RegistrationsBaseUrl/3.6.0",
		"RegistrationsBaseUrl/Versioned",
		"SearchQueryService",
		"SearchQueryService/3.0.0-rc",
		"SearchQueryService/3.5.0",
		"SearchAutocompleteService",
		"SearchAutocompleteService/3.5.0",
	}

	for _, t := range rewriteTypes {
		if serviceType == t {
			return true
		}
	}
	return false
}

// rewriteNuGetURL rewrites a NuGet API URL to point at this proxy.
func (h *NuGetHandler) rewriteNuGetURL(origURL string) string {
	// A custom upstream (e.g. Sonatype Firewall) advertises every service URL
	// under its own base; rewrite that base back to this proxy's /nuget/ path so
	// the client keeps talking to us.
	if h.upstreamURL != nugetUpstream && strings.HasPrefix(origURL, h.upstreamURL+"/") {
		return h.proxyURL + "/nuget/" + strings.TrimPrefix(origURL, h.upstreamURL+"/")
	}

	// Map known api.nuget.org endpoints to our proxy paths
	replacements := map[string]string{
		"https://api.nuget.org/v3-flatcontainer/":            h.proxyURL + "/nuget/v3-flatcontainer/",
		"https://api.nuget.org/v3/registration5-gz-semver2/": h.proxyURL + "/nuget/v3/registration5-gz-semver2/",
		"https://azuresearch-usnc.nuget.org/query":           h.proxyURL + "/nuget/query",
		"https://azuresearch-usnc.nuget.org/autocomplete":    h.proxyURL + "/nuget/autocomplete",
	}

	for old, new := range replacements {
		if strings.HasPrefix(origURL, old) {
			return strings.Replace(origURL, old, new, 1)
		}
	}

	return origURL
}

// handleRegistration proxies NuGet registration pages, applying cooldown filtering.
func (h *NuGetHandler) handleRegistration(w http.ResponseWriter, r *http.Request) {
	if h.proxy.Cooldown == nil || !h.proxy.Cooldown.Enabled() {
		h.proxyUpstream(w, r)
		return
	}

	upstreamURL := h.buildUpstreamURL(r)

	h.proxy.Logger.Debug("fetching registration for cooldown filtering", "url", upstreamURL)

	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, upstreamURL, nil)
	if err != nil {
		http.Error(w, "failed to create request", http.StatusInternalServerError)
		return
	}
	req.Header.Set(headerAcceptEncoding, "gzip")
	h.applyUpstreamAuth(req, upstreamURL)

	resp, err := h.proxy.HTTPClient.Do(req)
	if err != nil {
		h.proxy.Logger.Error("upstream request failed", "error", err)
		http.Error(w, "upstream request failed", http.StatusBadGateway)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		for k, vv := range resp.Header {
			for _, v := range vv {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
		return
	}

	body, err := h.proxy.ReadMetadata(resp.Body)
	if err != nil {
		http.Error(w, "failed to read response", http.StatusInternalServerError)
		return
	}

	filtered, err := h.applyCooldownFiltering(body)
	if err != nil {
		h.proxy.Logger.Warn("failed to filter registration, proxying original", "error", err)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(filtered)
}

// applyCooldownFiltering filters versions from NuGet registration pages
// that are too recently published.
func (h *NuGetHandler) applyCooldownFiltering(body []byte) ([]byte, error) {
	if h.proxy.Cooldown == nil || !h.proxy.Cooldown.Enabled() {
		return body, nil
	}

	var registration map[string]any
	if err := json.Unmarshal(body, &registration); err != nil {
		return nil, err
	}

	pages, ok := registration["items"].([]any)
	if !ok {
		return body, nil
	}

	for _, page := range pages {
		pageMap, ok := page.(map[string]any)
		if !ok {
			continue
		}

		items, ok := pageMap["items"].([]any)
		if !ok {
			continue
		}

		filtered := items[:0]
		for _, item := range items {
			itemMap, ok := item.(map[string]any)
			if !ok {
				continue
			}

			catalogEntry, ok := itemMap["catalogEntry"].(map[string]any)
			if !ok {
				filtered = append(filtered, item)
				continue
			}

			version, _ := catalogEntry["version"].(string)
			id, _ := catalogEntry["id"].(string)
			publishedStr, _ := catalogEntry["published"].(string)

			if publishedStr == "" {
				filtered = append(filtered, item)
				continue
			}

			publishedAt, err := time.Parse(time.RFC3339, publishedStr)
			if err != nil {
				// NuGet uses a slightly non-standard format, try parsing with fractional seconds
				publishedAt, err = time.Parse("2006-01-02T15:04:05.999-07:00", publishedStr)
				if err != nil {
					filtered = append(filtered, item)
					continue
				}
			}

			packagePURL := purl.MakePURLString("nuget", strings.ToLower(id), "")

			if !h.proxy.Cooldown.IsAllowed("nuget", packagePURL, publishedAt) {
				h.proxy.Logger.Info("cooldown: filtering nuget version",
					"package", id, "version", version,
					"published", publishedStr)
				continue
			}

			filtered = append(filtered, item)
		}

		pageMap["items"] = filtered
		pageMap["count"] = len(filtered)
	}

	return json.Marshal(registration)
}

// handleDownload serves a package file, fetching and caching from upstream if needed.
func (h *NuGetHandler) handleDownload(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	version := r.PathValue("version")
	filename := r.PathValue("filename")

	if id == "" || version == "" || filename == "" {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	// Only cache .nupkg files
	if !strings.HasSuffix(filename, ".nupkg") {
		h.proxyUpstream(w, r)
		return
	}

	h.proxy.Logger.Info("nuget download request",
		"id", id, "version", version, "filename", filename)

	// NuGet package IDs are case-insensitive, lowercase for storage
	name := strings.ToLower(id)
	upstreamURL := fmt.Sprintf("%s/v3-flatcontainer/%s/%s/%s", h.upstreamURL, name, version, filename)

	result, err := h.proxy.GetOrFetchArtifactFromURL(r.Context(), "nuget", name, version, filename, upstreamURL)
	if err != nil {
		h.proxy.writeArtifactError(w, err, "failed to fetch package")
		return
	}

	ServeArtifact(w, result)
}

// proxyUpstream forwards a request to NuGet without caching.
func (h *NuGetHandler) proxyUpstream(w http.ResponseWriter, r *http.Request) {
	// Build upstream URL based on the path
	upstreamURL := h.buildUpstreamURL(r)

	h.proxy.Logger.Debug("proxying to upstream", "url", upstreamURL)

	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, upstreamURL, nil)
	if err != nil {
		http.Error(w, "failed to create request", http.StatusInternalServerError)
		return
	}

	// Copy accept-encoding for compression
	if ae := r.Header.Get(headerAcceptEncoding); ae != "" {
		req.Header.Set(headerAcceptEncoding, ae)
	}
	h.applyUpstreamAuth(req, upstreamURL)

	resp, err := h.proxy.HTTPClient.Do(req)
	if err != nil {
		h.proxy.Logger.Error("upstream request failed", "error", err)
		http.Error(w, "upstream request failed", http.StatusBadGateway)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}

	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

// buildUpstreamURL constructs the upstream URL for a request.
func (h *NuGetHandler) buildUpstreamURL(r *http.Request) string {
	path := r.URL.Path

	// Search/autocomplete live on a separate host for api.nuget.org, but under the
	// same base for a custom upstream (e.g. Sonatype Firewall).
	if strings.HasPrefix(path, "/query") || strings.HasPrefix(path, "/autocomplete") {
		if h.upstreamURL == nugetUpstream {
			return "https://azuresearch-usnc.nuget.org" + path + "?" + r.URL.RawQuery
		}
		return h.upstreamURL + path + "?" + r.URL.RawQuery
	}

	return h.upstreamURL + path
}
