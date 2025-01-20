// Copyright 2024 Cofide Limited.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cert-manager/cert-manager/pkg/util/pki"
)

const testCertForFingerprinting = `-----BEGIN CERTIFICATE-----
MIICljCCAhugAwIBAgIUNAQr779ga/BNXyCpK7ddFbjAK98wCgYIKoZIzj0EAwMw
aTELMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExFjAUBgNVBAcTDVNh
biBGcmFuY2lzY28xHzAdBgNVBAoTFkludGVybmV0IFdpZGdldHMsIEluYy4xDDAK
BgNVBAsTA1dXVzAeFw0yMTAyMjYxMDM1MDBaFw0yMjAyMjYxMDM1MDBaMDMxCzAJ
BgNVBAYTAkdCMQ0wCwYDVQQKEwRjbmNmMRUwEwYDVQQLEwxjZXJ0LW1hbmFnZXIw
WTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATd5gWH2rkzWBGrr1jCR6JDB0dZOizZ
jCt2gnzNfzZmEg3rqxPvIakfT1lsjL2HrQyBRMQGGZhj7RkN7/VUM+VUo4HWMIHT
MA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIw
DAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQUCUEeUFyT7U3e6zP4q4VYEr2x0KcwHwYD
VR0jBBgwFoAUFkKAaJ18Vg9xFx3K7d5b7HjoSSMwVAYDVR0RBE0wS4IRY2VydC1t
YW5hZ2VyLnRlc3SBFHRlc3RAY2VydC1tYW5hZ2VyLmlvhwQKAAABhhpzcGlmZmU6
Ly9jZXJ0LW1hbmFnZXIudGVzdDAKBggqhkjOPQQDAwNpADBmAjEA3Fv1aP+dBtBh
+DThW0QQO/Xl0CHQRKnJmJ8JjnleaMYFVdHf7dcf0ZeyOC26aUkdAjEA/fvxvhcz
Dtj+gY2rewoeJv5Pslli+SEObUslRaVtUMGxwUbmPU2fKuZHWBfe2FfA
-----END CERTIFICATE-----
`

func Test_fingerprintCert(t *testing.T) {
	tests := []struct {
		name string
		cert *x509.Certificate
		want string
	}{
		{
			name: "Fingerprint a valid cert",
			cert: parseCert(t, testCertForFingerprinting),
			want: "FF:D0:A8:85:0B:A4:5A:E1:FC:55:40:E1:FC:07:09:F1:02:AE:B9:EB:28:C4:01:23:B9:4F:C8:FA:9B:EF:F4:C1",
		},
		{
			name: "Fingerprint nil",
			cert: nil,
			want: "",
		},
		{
			name: "Fingerprint invalid cert",
			cert: &x509.Certificate{Raw: []byte("fake")},
			want: "B5:D5:4C:39:E6:66:71:C9:73:1B:9F:47:1E:58:5D:82:62:CD:4F:54:96:3F:0C:93:08:2D:8D:CF:33:4D:4C:78",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := fingerprintCert(tt.cert); got != tt.want {
				t.Errorf("fingerprintCert() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_printCertInfo(t *testing.T) {
	template := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "cofide.io",
		},
		Issuer: pkix.Name{
			CommonName: "cofide.io",
		},
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
		SignatureAlgorithm:    x509.SHA256WithRSA,
		URIs:                  []*url.URL{parseURL("spiffe://cofide.io/test")},
	}

	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	cert, _ := x509.ParseCertificate(certDER)

	tests := []struct {
		name     string
		certs    []*x509.Certificate
		prefix   string
		contains []string
	}{
		{
			name:   "single CA certificate",
			certs:  []*x509.Certificate{cert},
			prefix: "  ",
			contains: []string{
				`  Certificate "`,
				"  Valid from",
				"  Subject: CN=cofide.io",
				"  URIs: spiffe://cofide.io/test",
				"  Signature algorithm: SHA256-RSA",
				"  Issuer: CN=cofide.io",
			},
		},
		{
			name:   "empty certificate list",
			certs:  []*x509.Certificate{},
			prefix: "  ",
		},
		{
			name:   "empty certificate list",
			certs:  []*x509.Certificate{nil},
			prefix: "  ",
			contains: []string{
				"  Error: nil certificate",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			old := os.Stdout
			r, w, _ := os.Pipe()
			os.Stdout = w

			printCertInfo(tt.certs, tt.prefix)

			w.Close()
			os.Stdout = old

			var buf bytes.Buffer
			io.Copy(&buf, r)
			output := buf.String()

			for _, expected := range tt.contains {
				if !strings.Contains(output, expected) {
					t.Errorf("expected output to contain %q, got %q", expected, output)
				}
			}
		})
	}
}

func parseCert(t *testing.T, certData string) *x509.Certificate {
	x509Cert, err := pki.DecodeX509CertificateBytes([]byte(certData))
	if err != nil {
		t.Fatalf("error when parsing crt: %v", err)
	}

	return x509Cert
}

func parseURL(s string) *url.URL {
	u, _ := url.Parse(s)
	return u
}
