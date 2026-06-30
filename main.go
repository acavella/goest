package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"gopkg.in/yaml.v3"
)

const (
	ESTPathCACerts        = "/.well-known/est/cacerts"
	ESTPathSimpleEnroll   = "/.well-known/est/simpleenroll"
	ESTPathSimpleReenroll = "/.well-known/est/simplereenroll"
)

// Config represents the application configuration from a YAML file.
type Config struct {
	Server      ServerConfig      `yaml:"server"`
	Credentials CredentialsConfig `yaml:"credentials"`
	Client      ClientConfig      `yaml:"client"`
}

type ServerConfig struct {
	Address       string `yaml:"address"`
	SecurePort    int    `yaml:"secure_port"`
	NonSecurePort int    `yaml:"non_secure_port"`
}

type CredentialsConfig struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

type ClientConfig struct {
	CommonName string `yaml:"common_name"`
}

// LoadConfig reads and parses the YAML configuration file.
func LoadConfig(filename string) (*Config, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %v", err)
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %v", err)
	}

	return &config, nil
}

// ESTClient holds the configuration for connecting to an EST server.
type ESTClient struct {
	ServerURL string
	Client    *http.Client
}

// NewESTClient initializes an EST client. 
// NOTE: For demonstration, InsecureSkipVerify is used. In production, provide the specific Root CA pool!
func NewESTClient(serverURL string, clientCert *tls.Certificate) *ESTClient {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true, // IMPORTANT: Change this in production to validate the EST server's TLS cert
	}

	// If a client cert is provided, this prepares the client for Mutual TLS (required for Re-enrollment)
	if clientCert != nil {
		tlsConfig.Certificates = []tls.Certificate{*clientCert}
	}

	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	return &ESTClient{
		ServerURL: serverURL,
		Client:    &http.Client{Transport: transport},
	}
}

// GenerateCSR creates a new RSA keypair and a Certificate Signing Request (CSR).
func GenerateCSR(commonName string) ([]byte, *rsa.PrivateKey, error) {
	// 1. Generate RSA Key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate RSA key: %v", err)
	}

	// 2. Create CSR Template
	template := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: commonName,
		},
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	// 3. Create the CSR
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &template, privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create CSR: %v", err)
	}

	return csrDER, privateKey, nil
}

// SimpleEnroll performs initial certificate enrollment using Basic Authentication.
func (c *ESTClient) SimpleEnroll(username, password string, csrDER []byte) ([]byte, error) {
	// EST requires the CSR to be base64 encoded
	b64CSR := base64.StdEncoding.EncodeToString(csrDER)
	req, err := http.NewRequest("POST", c.ServerURL+ESTPathSimpleEnroll, bytes.NewBufferString(b64CSR))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/pkcs10")
	req.SetBasicAuth(username, password)

	resp, err := c.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("enroll request failed: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned status %d: %s", resp.StatusCode, string(body))
	}

	// Returns a base64 encoded PKCS#7 bundle containing the new certificate
	return body, nil
}

// SimpleReenroll performs certificate renewal using an existing Client Certificate (Mutual TLS).
func (c *ESTClient) SimpleReenroll(csrDER []byte) ([]byte, error) {
	// EST requires the CSR to be base64 encoded
	b64CSR := base64.StdEncoding.EncodeToString(csrDER)
	req, err := http.NewRequest("POST", c.ServerURL+ESTPathSimpleReenroll, bytes.NewBufferString(b64CSR))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/pkcs10")

	// Notice: No Basic Auth here. Authentication relies on Mutual TLS provided during ESTClient setup.
	resp, err := c.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("re-enroll request failed: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned status %d: %s", resp.StatusCode, string(body))
	}

	// Returns a base64 encoded PKCS#7 bundle
	return body, nil
}

func main() {
	fmt.Println("=== Loading Configuration ===")
	cfg, err := LoadConfig("config.yaml")
	if err != nil {
		log.Fatalf("Error loading config: %v", err)
	}

	// Construct the URL based on the config. EST usually runs over the secure port.
	estServerURL := fmt.Sprintf("https://%s:%d", cfg.Server.Address, cfg.Server.SecurePort)

	fmt.Println("=== Starting EST Client ===")

	// 1. Generate CSR & Private Key for initial enrollment
	fmt.Println("[1] Generating CSR for initial enrollment...")
	csrDER, privateKey, err := GenerateCSR(cfg.Client.CommonName)
	if err != nil {
		log.Fatalf("Error generating CSR: %v", err)
	}

	// 2. Perform Initial Enrollment
	fmt.Println("[2] Performing Simple Enroll (Basic Auth)...")
	client := NewESTClient(estServerURL, nil) // No client cert yet
	
	pkcs7B64, err := client.SimpleEnroll(cfg.Credentials.Username, cfg.Credentials.Password, csrDER)
	if err != nil {
		log.Fatalf("Enrollment failed: %v\nNote: If using testrfc7030.com, it might be offline or require specific CAs.", err)
	}
	
	fmt.Println("Enrollment successful! Received PKCS7 payload.")
	// (In a real app, you would parse the PKCS7 base64 payload here to extract your x509.Certificate.
	// You might use a package like go.mozilla.org/pkcs7 for this).

	// For demonstration purposes, we will mock creating a tls.Certificate so we can show re-enrollment.
	// Assume 'parsedCert' is the x509.Certificate extracted from pkcs7B64
	
	/* --- RE-ENROLLMENT DEMO --- */
	
	// fmt.Println("[3] Performing Simple Re-enroll (Mutual TLS)...")
	//
	// tlsCert := &tls.Certificate{
	// 	Certificate: [][]byte{parsedCert.Raw},
	// 	PrivateKey:  privateKey,
	// }
	// mtlsClient := NewESTClient(estServerURL, tlsCert)
	// 
	// newCsrDER, _, _ := GenerateCSR(cfg.Client.CommonName) // Usually a new key is generated
	// reenrollPkcs7B64, err := mtlsClient.SimpleReenroll(newCsrDER)
	// if err != nil {
	// 	log.Fatalf("Re-enrollment failed: %v", err)
	// }
	// fmt.Println("Re-enrollment successful!")
}
