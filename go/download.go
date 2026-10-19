package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func (e *engine) download() (string, func(), error) {
	u, err := url.Parse(e.o.source)
	if err != nil || u.Host == "" || u.User != nil || (u.Scheme != "http" && u.Scheme != "https") {
		// Never echo credential-bearing URLs.
		return "", nil, fail("NETWORK_ERROR", "URL", "invalid URL or URL credentials are forbidden")
	}
	transport := &http.Transport{Proxy: http.ProxyFromEnvironment, DisableCompression: true, DialContext: (&net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}).DialContext, TLSHandshakeTimeout: 15 * time.Second, ResponseHeaderTimeout: 30 * time.Second}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 2 * time.Minute, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) > 5 {
			return fmt.Errorf("redirect limit exceeded")
		}
		if req.URL.User != nil || (req.URL.Scheme != "http" && req.URL.Scheme != "https") {
			return fmt.Errorf("unsafe redirect")
		}
		if len(via) > 0 && via[len(via)-1].URL.Scheme == "https" && req.URL.Scheme != "https" {
			return fmt.Errorf("HTTPS downgrade")
		}
		return nil
	}}
	parent := e.o.ctx
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithTimeout(parent, 2*time.Minute)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", nil, fail("NETWORK_ERROR", "URL", "invalid request")
	}
	request.Header.Set("Accept-Encoding", "identity")
	response, err := client.Do(request)
	if err != nil {
		return "", nil, fail("NETWORK_ERROR", "URL", "HTTP transfer or redirect failed")
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return "", nil, fail("NETWORK_ERROR", "URL", "unsuccessful HTTP status")
	}
	if coding := response.Header.Get("Content-Encoding"); coding != "" && !strings.EqualFold(strings.TrimSpace(coding), "identity") {
		return "", nil, fail("NETWORK_ERROR", "URL", "non-identity HTTP content coding")
	}
	if response.ContentLength >= 0 && uint64(response.ContentLength) > e.o.download {
		return "", nil, fail("LIMIT_EXCEEDED", "URL", "download byte limit exceeded")
	}
	dir, err := privateDownloadDirectory()
	if err != nil {
		return "", nil, fail("IO_ERROR", "URL", "cannot create private download directory")
	}
	cleanup := func() { _ = os.RemoveAll(dir) }
	name := filepath.Join(dir, "payload")
	f, err := os.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		cleanup()
		return "", nil, fail("IO_ERROR", "URL", "cannot create private download file")
	}
	buf := make([]byte, 32768)
	var count uint64
	for {
		n, readErr := response.Body.Read(buf)
		if n > 0 {
			if uint64(n) > e.o.download-count {
				_ = f.Close()
				cleanup()
				return "", nil, fail("LIMIT_EXCEEDED", "URL", "download byte limit exceeded")
			}
			count += uint64(n)
			if _, err = f.Write(buf[:n]); err != nil {
				_ = f.Close()
				cleanup()
				return "", nil, fail("IO_ERROR", "URL", "cannot write download")
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			_ = f.Close()
			cleanup()
			return "", nil, fail("NETWORK_ERROR", "URL", "truncated or failed HTTP body")
		}
	}
	if err = f.Close(); err != nil {
		cleanup()
		return "", nil, fail("IO_ERROR", "URL", "cannot close download")
	}
	return name, cleanup, nil
}
