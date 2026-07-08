// Package fetchcb wraps a fetch.FetcherInterface with per-registry circuit
// breakers that trip only on genuine upstream unavailability.
//
// The stock circuit breaker in github.com/git-pkgs/registries counts every
// non-nil fetch error as a failure. That conflates a real outage with a valid
// client response: a 404, or any 4xx such as a 403 policy block from Sonatype
// Firewall, is returned as an error and therefore trips the breaker. Because the
// breaker is keyed by upstream host, all ecosystems fronted by one host (e.g.
// firewall.sonatype.app for npm, PyPI and Maven) share a single breaker, so
// blocking a run of malicious packages opens it and the healthy packages that
// follow start failing with 502. This wrapper fixes that: a client response
// (404 / 4xx) is passed back to the caller but does NOT count against the
// breaker; only 5xx, rate limiting and transport errors do.
package fetchcb

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"sync"
	"time"

	"github.com/cenk/backoff"
	circuit "github.com/rubyist/circuitbreaker"

	"github.com/git-pkgs/registries/fetch"
)

const (
	initialInterval = 30 * time.Second
	maxInterval     = 5 * time.Minute
	threshold       = 5
	maxURLTruncate  = 50
)

// Fetcher is a policy-aware circuit-breaker wrapper around a fetch.FetcherInterface.
type Fetcher struct {
	base     fetch.FetcherInterface
	mu       sync.RWMutex
	breakers map[string]*circuit.Breaker
}

// New wraps base with per-registry circuit breakers.
func New(base fetch.FetcherInterface) *Fetcher {
	return &Fetcher{base: base, breakers: make(map[string]*circuit.Breaker)}
}

func (f *Fetcher) breaker(registry string) *circuit.Breaker {
	f.mu.RLock()
	b, ok := f.breakers[registry]
	f.mu.RUnlock()
	if ok {
		return b
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	if b, ok := f.breakers[registry]; ok {
		return b
	}

	bo := backoff.NewExponentialBackOff()
	bo.InitialInterval = initialInterval
	bo.MaxInterval = maxInterval
	bo.Multiplier = 2.0
	bo.Reset()

	b = circuit.NewBreakerWithOptions(&circuit.Options{
		BackOff:    bo,
		ShouldTrip: circuit.ThresholdTripFunc(threshold),
	})
	f.breakers[registry] = b
	return b
}

// Fetch downloads an artifact from url.
func (f *Fetcher) Fetch(ctx context.Context, url string) (*fetch.Artifact, error) {
	return f.FetchWithHeaders(ctx, url, nil)
}

// FetchWithHeaders downloads an artifact from url with additional headers.
func (f *Fetcher) FetchWithHeaders(ctx context.Context, url string, headers http.Header) (*fetch.Artifact, error) {
	registry := registryOf(url)
	b := f.breaker(registry)
	if !b.Ready() {
		return nil, breakerOpen(registry)
	}

	var (
		artifact *fetch.Artifact
		fetchErr error
		ran      bool
	)
	_ = b.Call(func() error {
		ran = true
		artifact, fetchErr = f.base.FetchWithHeaders(ctx, url, headers)
		if tripsBreaker(fetchErr) {
			return fetchErr
		}
		return nil // success or client response: do not count against the breaker
	}, 0)
	if !ran {
		return nil, breakerOpen(registry)
	}
	return artifact, fetchErr
}

// Head checks an artifact's existence/metadata without downloading it.
func (f *Fetcher) Head(ctx context.Context, headURL string) (size int64, contentType string, err error) {
	registry := registryOf(headURL)
	b := f.breaker(registry)
	if !b.Ready() {
		return 0, "", breakerOpen(registry)
	}

	var (
		headErr error
		ran     bool
	)
	_ = b.Call(func() error {
		ran = true
		size, contentType, headErr = f.base.Head(ctx, headURL)
		if tripsBreaker(headErr) {
			return headErr
		}
		return nil
	}, 0)
	if !ran {
		return 0, "", breakerOpen(registry)
	}
	return size, contentType, headErr
}

func breakerOpen(registry string) error {
	return fmt.Errorf("circuit breaker open for registry %s: %w", registry, fetch.ErrUpstreamDown)
}

func registryOf(raw string) string {
	if parsed, err := url.Parse(raw); err == nil && parsed.Host != "" {
		return parsed.Host
	}
	if len(raw) > maxURLTruncate {
		return raw[:maxURLTruncate]
	}
	return raw
}

var upstreamStatusRe = regexp.MustCompile(`unexpected status (\d+)`)

// tripsBreaker reports whether a fetch error should count as a circuit-breaker
// failure. Client responses are valid answers from a healthy upstream and must
// NOT trip the breaker: a 404 (fetch.ErrNotFound), any 4xx such as a 403 policy
// block, or a caller-cancelled context. Genuine unavailability does: 5xx
// (fetch.ErrUpstreamDown), rate limiting (fetch.ErrRateLimited) and transport
// errors.
func tripsBreaker(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, fetch.ErrNotFound) {
		return false
	}
	if errors.Is(err, fetch.ErrUpstreamDown) || errors.Is(err, fetch.ErrRateLimited) {
		return true
	}
	if m := upstreamStatusRe.FindStringSubmatch(err.Error()); m != nil {
		if code, convErr := strconv.Atoi(m[1]); convErr == nil && code >= 400 && code < 500 {
			return false
		}
	}
	return true
}
