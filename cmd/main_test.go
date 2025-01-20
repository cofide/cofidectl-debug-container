// Copyright 2024 Cofide Limited.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cert-manager/cert-manager/pkg/util/pki"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/stretchr/testify/assert"
)

const testCert = `-----BEGIN CERTIFICATE-----
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

func Test_displayBundles(t *testing.T) {
	tests := []struct {
		name    string
		bundles *x509bundle.Set
		want    []string
	}{
		{
			name:    "nil bundles",
			bundles: nil,
			want: []string{
				"No trust bundles available",
			},
		},
		{
			name:    "empty bundles",
			bundles: createEmptyBundleSet(t),
			want: []string{
				"Trust bundles received",
				"<none>",
			},
		},
		{
			name:    "single bundle with no authorities",
			bundles: createBundleSetWithoutAuthority(t),
			want: []string{
				"Trust bundles received",
				"* spiffe://domain.test",
			},
		},
		{
			name:    "single bundle with one authority",
			bundles: createBundleSetWithAuthority(t),
			want: []string{
				"Trust bundles received",
				"* spiffe://domain.test",
				"  Certificate ",
				"  Valid from",
				"  Subject: CN=cofide.io",
				"  URIs: spiffe://domain.test",
				"  Signature algorithm: SHA256-RSA",
				"  Issuer: CN=cofide.io",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output := captureOutput(t, func() {
				displayBundles(tt.bundles)
			})

			for _, want := range tt.want {
				assert.Contains(t, output, want)
			}
		})
	}
}

func Test_displaySVIDs(t *testing.T) {
	svid := createTestSVID(t, "domain.test", "/workload")
	bundleSet := createBundleSetWithCert(t, svid.Certificates[0])

	tests := []struct {
		name  string
		svids []*x509svid.SVID
		want  []string
	}{
		{
			name:  "nil svids",
			svids: nil,
			want: []string{
				"SVIDs received",
				"<none>",
			},
		},
		{
			name:  "empty svids",
			svids: []*x509svid.SVID{},
			want: []string{
				"SVIDs received",
				"<none>",
			},
		},
		{
			name:  "single svid",
			svids: []*x509svid.SVID{svid},
			want: []string{
				"SVIDs received",
				"* spiffe://domain.test/workload",
				"Certificate",
				"Valid from",
				"Subject: CN=test.domain.test",
				"URIs: spiffe://domain.test/workload",
				"SVID verified against trust bundle",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output := captureOutput(t, func() {
				displaySVIDs(tt.svids, bundleSet)
			})

			for _, want := range tt.want {
				assert.Contains(t, output, want)
			}
		})
	}
}

func Test_verifySVID(t *testing.T) {
	template := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "test.domain.test",
		},
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true,
		URIs:                  []*url.URL{parseURL("spiffe://domain.test/workload")},
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	svid := &x509svid.SVID{
		ID:           spiffeid.RequireFromPath(spiffeid.RequireTrustDomainFromString("domain.test"), "/workload"),
		Certificates: []*x509.Certificate{cert},
	}

	tests := []struct {
		name    string
		svid    *x509svid.SVID
		bundles *x509bundle.Set
		wantErr bool
		want    string
	}{
		{
			name:    "valid SVID with matching bundle",
			svid:    svid,
			bundles: createBundleSetWithCert(t, cert),
			wantErr: false,
		},
		{
			name:    "valid SVID with non-matching bundle",
			svid:    svid,
			bundles: createBundleSet(t),
			wantErr: true,
			want:    "SVID verification failed: x509: certificate signed by unknown authority",
		},
		{
			name:    "nil SVID",
			svid:    nil,
			bundles: createBundleSet(t),
			wantErr: true,
			want:    "SVID is nil",
		},
		{
			name:    "empty bundle set",
			svid:    svid,
			bundles: createEmptyBundleSet(t),
			wantErr: true,
			want:    fmt.Sprintf("failed to get bundle for trust domain \"%s\": x509bundle: no X.509 bundle for trust domain \"%s\"", svid.ID.TrustDomain().IDString(), svid.ID.TrustDomain().String()),
		},
		{
			name:    "nil bundle set",
			svid:    svid,
			bundles: nil,
			wantErr: true,
			want:    "bundles is nil",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := verifySVID(tt.svid, tt.bundles)
			if (err != nil) != tt.wantErr {
				t.Errorf("verifySVID() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				assert.EqualError(t, err, tt.want)
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
		URIs:                  []*url.URL{parseURL("spiffe://domain.test")},
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
				"  Certificate ",
				"  Valid from",
				"  Subject: CN=cofide.io",
				"  URIs: spiffe://domain.test",
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
			output := captureOutput(t, func() {
				printCertInfo(tt.certs, tt.prefix)
			})

			for _, want := range tt.contains {
				if !strings.Contains(output, want) {
					t.Errorf("want output to contain %q, got %q", want, output)
				}
			}
		})
	}
}

func Test_fingerprintCert(t *testing.T) {
	tests := []struct {
		name string
		cert *x509.Certificate
		want string
	}{
		{
			name: "Fingerprint a valid cert",
			cert: parseCert(t, testCert),
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

// createTestCertificate creates a test certificate for testing.
func createTestCertificate(t *testing.T, cn string, uris ...string) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	if cn == "" {
		t.Fatal("Common Name cannot be empty")
	}

	template := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: cn,
		},
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true,
	}

	if len(uris) > 0 {
		template.URIs = make([]*url.URL, len(uris))
		for i, uri := range uris {
			template.URIs[i] = parseURL(uri)
		}
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	return cert, privateKey
}

// createTestSVID creates an SVID for testing.
func createTestSVID(t *testing.T, td, path string) *x509svid.SVID {
	cert, _ := createTestCertificate(t, "test."+td, "spiffe://"+td+path)
	return &x509svid.SVID{
		ID:           spiffeid.RequireFromPath(spiffeid.RequireTrustDomainFromString(td), path),
		Certificates: []*x509.Certificate{cert},
	}
}

func createBundleSet(t *testing.T) *x509bundle.Set {
	td, err := spiffeid.TrustDomainFromString("domain.test")
	if err != nil {
		t.Fatalf("Failed to create trust domain: %v", err)
	}
	bundle := x509bundle.New(td)
	return x509bundle.NewSet(bundle)
}

func createEmptyBundleSet(t *testing.T) *x509bundle.Set {
	return x509bundle.NewSet()
}

func createBundleSetWithoutAuthority(t *testing.T) *x509bundle.Set {
	td, err := spiffeid.TrustDomainFromString("domain.test")
	if err != nil {
		t.Fatalf("Failed to create trust domain: %v", err)
	}
	bundle := x509bundle.New(td)
	set := x509bundle.NewSet(bundle)
	return set
}

func createBundleSetWithAuthority(t *testing.T) *x509bundle.Set {
	td, err := spiffeid.TrustDomainFromString("domain.test")
	if err != nil {
		t.Fatalf("Failed to create trust domain: %v", err)
	}

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
		URIs:                  []*url.URL{parseURL("spiffe://domain.test")},
	}

	bundle := x509bundle.New(td)
	bundle.AddX509Authority(template)
	set := x509bundle.NewSet(bundle)
	return set
}

func createBundleSetWithCert(t *testing.T, cert *x509.Certificate) *x509bundle.Set {
	td, err := spiffeid.TrustDomainFromString("domain.test")
	if err != nil {
		t.Fatalf("Failed to create trust domain: %v", err)
	}
	bundle := x509bundle.New(td)
	bundle.AddX509Authority(cert)
	return x509bundle.NewSet(bundle)
}

// captureOutput captures the output of a function and returns it as a string.
func captureOutput(t *testing.T, fn func()) string {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	fn()

	w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	_, err := io.Copy(&buf, r)
	if err != nil {
		t.Fatalf("Failed to copy output: %v", err)
	}

	return buf.String()
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
