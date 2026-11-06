package core

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHTTPGetRejectsSelfSigned(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer srv.Close()
	_, _, _, err := HTTPGet(context.Background(), srv.URL, nil)
	if err == nil {
		t.Fatalf("expected TLS verification failure")
	}
}

func TestHTTPGetInsecureAcceptsSelfSigned(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer srv.Close()
	status, _, body, err := HTTPGetInsecure(context.Background(), srv.URL, nil)
	if err != nil {
		t.Fatalf("insecure failed: %v", err)
	}
	if status != 200 || string(body) != "ok" {
		t.Fatalf("bad: status=%d body=%q", status, body)
	}
}

func TestHTTPGetBodyLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(make([]byte, MaxBodySize+100))
	}))
	defer srv.Close()
	_, _, _, err := HTTPGet(context.Background(), srv.URL, nil)
	if err != ErrResponseTooLarge {
		t.Fatalf("expected ErrResponseTooLarge, got %v", err)
	}
}
