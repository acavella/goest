# **GoEST: Secure Enrollment Client**

This project is a lightweight Golang client for Enrollment over Secure Transport (EST) as defined in [RFC 7030](https://datatracker.ietf.org/doc/html/rfc7030).

It provides the scaffolding necessary to securely request x509 certificates from an EST Server and renew them.

## **Features Included**

* **RSA Keypair Generation**: Programmatically generates private keys and Certificate Signing Requests (CSRs).  
* **Initial Enrollment (/simpleenroll)**: Supports provisioning a new device via HTTP Basic Authentication.  
* **Re-enrollment (/simplereenroll)**: Configures the HTTP transport to utilize Mutual TLS (mTLS) with your existing certificate to authenticate requests for renewals.

## **Prerequisites**

* [Go](https://golang.org/dl/) (version 1.22)  
* gopkg.in/yaml.v3 (for configuration parsing)

## **Security Warning**

By default, the NewESTClient function in this demo uses InsecureSkipVerify: true to bypass server TLS certificate validation. **You must change this in a production environment** by providing the EST server's Root CA to the tls.Config.RootCAs pool.

## **Getting Started**

1. **Configure the client**:  
   Update the config.yaml file with your EST server's address, ports, and desired credentials.  
2. **Run the client**:  
   go run main.go

## **Handling PKCS\#7 Payloads**

The EST protocol mandates that servers respond to enrollment requests with a Base64 encoded "certs-only" PKCS\#7 payload.

Because the Go standard library does not natively parse PKCS\#7, you will likely want to install a third-party module to extract your new certificate from the response body. We recommend go.mozilla.org/pkcs7:

go get go.mozilla.org/pkcs7

Once installed, you can parse the returned pkcs7B64 payload like this:

```golang
decoded, \_ := base64.StdEncoding.DecodeString(string(pkcs7B64))  
p7, err := pkcs7.Parse(decoded)  
if err \== nil && len(p7.Certificates) \> 0 {  
    myNewCert := p7.Certificates\[0\]  
    // Save or use myNewCert...  
}
```

