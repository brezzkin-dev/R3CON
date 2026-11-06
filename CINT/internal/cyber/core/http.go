package core

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"time"
)

var ErrResponseTooLarge = errors.New("response exceeds max body size")

const MaxBodySize int64 = 16 << 20

var verifiedClient = &http.Client{
	Timeout: 15 * time.Second,
	Transport: &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     30 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	},
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return http.ErrUseLastResponse
		}
		return nil
	},
}

var insecureClient = &http.Client{
	Timeout: 15 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     30 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	},
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return http.ErrUseLastResponse
		}
		return nil
	},
}

func doGet(ctx context.Context, client *http.Client, url string, headers map[string]string) (int, http.Header, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return 0, nil, nil, err
	}
	req.Header.Set("User-Agent", "L1ghtXr/1.0")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxBodySize+1))
	if err != nil {
		return resp.StatusCode, resp.Header, nil, err
	}
	if int64(len(body)) > MaxBodySize {
		return resp.StatusCode, resp.Header, nil, ErrResponseTooLarge
	}
	return resp.StatusCode, resp.Header, body, nil
}

func HTTPGet(ctx context.Context, url string, headers map[string]string) (int, http.Header, []byte, error) {
	return doGet(ctx, verifiedClient, url, headers)
}

func HTTPGetInsecure(ctx context.Context, url string, headers map[string]string) (int, http.Header, []byte, error) {
	return doGet(ctx, insecureClient, url, headers)
}

func HTTPPost(ctx context.Context, url, ct string, body []byte, headers map[string]string) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("User-Agent", "L1ghtXr/1.0")
	req.Header.Set("Content-Type", ct)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := verifiedClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, MaxBodySize+1))
	if err != nil {
		return resp.StatusCode, nil, err
	}
	if int64(len(b)) > MaxBodySize {
		return resp.StatusCode, nil, ErrResponseTooLarge
	}
	return resp.StatusCode, b, nil
}
