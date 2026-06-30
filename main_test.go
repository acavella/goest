package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestHealthCheckHandler ensures the /health endpoint returns the correct status and payload.
func TestHealthCheckHandler(t *testing.T) {
	// 1. Create a request to pass to our handler.
	// We don't have any query parameters, so we pass 'nil' as the third argument.
	req, err := http.NewRequest("GET", "/health", nil)
	if err != nil {
		t.Fatal(err)
	}

	// 2. We create a ResponseRecorder (which satisfies http.ResponseWriter) to record the response.
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(healthCheckHandler)

	// 3. Our handlers satisfy http.Handler, so we can call their ServeHTTP method
	// directly and pass in our Request and ResponseRecorder.
	handler.ServeHTTP(rr, req)

	// 4. Check the status code is what we expect (200 OK).
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	// 5. Check the response body is what we expect.
	var response Response
	err = json.Unmarshal(rr.Body.Bytes(), &response)
	if err != nil {
		t.Fatalf("failed to parse response body: %v", err)
	}

	if response.Status != "success" {
		t.Errorf("handler returned unexpected status in body: got %v want %v",
			response.Status, "success")
	}
}
