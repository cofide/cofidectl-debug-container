// Copyright 2024 Cofide Limited.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"log"
	"log/slog"
	"strings"
	"time"

	"github.com/spiffe/go-spiffe/v2/logger"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

const spiffeSocket = "unix:///spiffe-workload-api/spire-agent.sock"

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client, err := workloadapi.New(ctx, workloadapi.WithAddr(spiffeSocket), workloadapi.WithLogger(logger.Std))

	if err != nil {
		log.Fatalf("Unable to create workload API client: %v", err)
	}

	bundles, err := client.FetchX509Bundles(ctx)
	if err != nil {
		slog.Warn("unable to fetch X.509 trust bundles", "error", err)
	}

	svids, err := client.FetchX509SVIDs(ctx)
	if err != nil {
		slog.Warn("unable to fetch X.509 SVIDs", "error", err)
	}

	// closing client before end of run so we have a clean output
	client.Close()

	if bundles != nil {
		fmt.Println("Trust bundles received")
		if len(bundles.Bundles()) == 0 {
			fmt.Println("<none>")
		}

		for _, b := range bundles.Bundles() {
			fmt.Printf("* %s\n", b.TrustDomain().IDString())
			printCertInfo(b.X509Authorities(), "    ")
		}
	}

	fmt.Println("\nSVIDs received")
	if len(svids) == 0 {
		fmt.Println("<none>")
	}

	for _, s := range svids {
		fmt.Printf("* %s\n", s.ID.URL().String())
		printCertInfo(s.Certificates, "    ")

		// verify the SVID against the trust bundle
		if bundles != nil {
			if bundle, err := bundles.GetX509BundleForTrustDomain(s.ID.TrustDomain()); bundle != nil || err == nil {
				// verify the SVID against the trust bundle
				verifier := x509.NewCertPool()
				for _, ca := range bundle.X509Authorities() {
					verifier.AddCert(ca)
				}

				_, err = s.Certificates[0].Verify(x509.VerifyOptions{
					Roots:         verifier,
					CurrentTime:   time.Now(),
					Intermediates: x509.NewCertPool(),
				})
				if err != nil {
					fmt.Printf("    SVID verification failed: %v\n", err)
				} else {
					fmt.Printf("    SVID verified against trust bundle\n")
				}
			} else {
				fmt.Printf("    No trust bundle found for trust domain %q\n", s.ID.TrustDomain().IDString())
			}
		}
	}
}

func printCertInfo(certs []*x509.Certificate, prefix string) {
	for i, c := range certs {
		fmt.Printf("%sCertificate %q\n", prefix, fingerprintCert(c))
		if c.IsCA {
			fmt.Printf("%sis a CA certificate\n", prefix)
		}
		fmt.Printf("%svalid from %q to %q\n", prefix, c.NotBefore.Format(time.RFC3339), c.NotAfter.Format(time.RFC3339))
		if c.Subject.String() != "" {
			fmt.Printf("%sSubject: %s\n", prefix, c.Subject.String())
		}

		if len(c.URIs) > 0 {
			uris := make([]string, 0, len(c.URIs))
			for _, uri := range c.URIs {
				uris = append(uris, uri.String())
			}
			fmt.Printf("%sDNS names: %s\n", prefix, strings.Join(uris, ", "))
		}

		fmt.Printf("%sSignature algorithm: %s\n", prefix, c.SignatureAlgorithm)
		fmt.Printf("%sIssuer: %s\n", prefix, c.Issuer.String())

		if i < len(certs)-1 {
			fmt.Println()
		}
	}
}

// fingerprintCert returns the SHA-256 fingerprint of the certificate
func fingerprintCert(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	fingerprint := sha256.Sum256(cert.Raw)

	var buf bytes.Buffer
	for i, f := range fingerprint {
		if i > 0 {
			fmt.Fprintf(&buf, ":")
		}
		fmt.Fprintf(&buf, "%02X", f)
	}

	return buf.String()
}
