package main

import (
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestGenerateCSR verifies that the CSR and private key are generated correctly
func TestGenerateCSR(t *testing.T) {
	expectedCN := "device-001.test.com"
	csrDER, privateKey, err := GenerateCSR(expectedCN)

	if err != nil {
		t.Fatalf("GenerateCSR failed: %v", err)
	}

	if privateKey == nil {
		t.Error("Expected a generated RSA private key, got nil")
	}

	if len(csrDER) == 0 {
		t.Fatal("Expected CSR DER bytes, got an empty slice")
	}

	// Parse the generated CSR to ensure it's valid and has the right Common Name
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatalf("Failed to parse generated CSR: %v", err)
	}

	if csr.Subject.CommonName != expectedCN {
		t.Errorf("Expected CSR Common Name to be %q, got %q", expectedCN, csr.Subject.CommonName)
	}
}

// TestSimpleEnroll verifies the client correctly formats and sends an enrollment request
func TestSimpleEnroll(t *testing.T) {
	// 1. Create a mock EST server to intercept our client's request
	mockServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check that it's hitting the correct path
		if r.URL.Path != ESTPathSimpleEnroll {
			t.Errorf("Expected request to %s, got %s", ESTPathSimpleEnroll, r.URL.Path)
		}

		// Check HTTP method
		if r.Method != http.MethodPost {
			t.Errorf("Expected POST method, got %s", r.Method)
		}

		// Check headers
		if ct := r.Header.Get("Content-Type"); ct != "application/pkcs10" {
			t.Errorf("Expected Content-Type application/pkcs10, got %s", ct)
		}

		// Check Basic Auth credentials
		user, pass, ok := r.BasicAuth()
		if !ok || user != "testuser" || pass != "testpass" {
			t.Errorf("Missing or incorrect basic auth credentials")
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Send back a mock PKCS7 response payload
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("mock-pkcs7-payload"))
	}))
	defer mockServer.Close()

	// 2. Set up our EST Client to point to the mock server
	client := NewESTClient(mockServer.URL, nil)
	// Override the client to use the mock server's client (so it trusts the mock TLS cert)
	client.Client = mockServer.Client()

	// 3. Execute the function
	dummyCSR := []byte("dummy-csr-data")
	resp, err := client.SimpleEnroll("testuser", "testpass", dummyCSR)

	if err != nil {
		t.Fatalf("SimpleEnroll returned an error: %v", err)
	}

	// 4. Verify the response
	if string(resp) != "mock-pkcs7-payload" {
		t.Errorf("Expected response 'mock-pkcs7-payload', got '%s'", string(resp))
	}
}

// TestSimpleReenroll verifies the re-enrollment request omits basic auth and hits the right path
func TestSimpleReenroll(t *testing.T) {
	mockServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != ESTPathSimpleReenroll {
			t.Errorf("Expected request to %s, got %s", ESTPathSimpleReenroll, r.URL.Path)
		}

		// Re-enrollment should NOT use basic auth (relies on mutual TLS instead)
		_, _, ok := r.BasicAuth()
		if ok {
			t.Errorf("Did not expect Basic Auth to be present on Re-enrollment")
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("mock-reenroll-payload"))
	}))
	defer mockServer.Close()

	client := NewESTClient(mockServer.URL, nil)
	client.Client = mockServer.Client()

	dummyCSR := []byte("dummy-csr-data")
	resp, err := client.SimpleReenroll(dummyCSR)

	if err != nil {
		t.Fatalf("SimpleReenroll returned an error: %v", err)
	}

	if string(resp) != "mock-reenroll-payload" {
		t.Errorf("Expected response 'mock-reenroll-payload', got '%s'", string(resp))
	}
}