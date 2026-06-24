package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey_Success(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "ApiKey test-api-key")

	apiKey, err := GetAPIKey(headers)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if apiKey != "test-api-key" {
		t.Fatalf("expected api key %q, got %q", "test-api-key", apiKey)
	}
}

func TestGetAPIKey_NoAuthorizationHeader(t *testing.T) {
	headers := http.Header{}

	_, err := GetAPIKey(headers)
	if err != ErrNoAuthHeaderIncluded {
		t.Fatalf("expected ErrNoAuthHeaderIncluded, got %v", err)
	}
}

func TestGetAPIKey_MalformedAuthorizationHeader(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "Bearer test-api-key")

	_, err := GetAPIKey(headers)
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if err.Error() != "malformed authorization header" {
		t.Fatalf("unexpected error: %v", err)
	}
}
