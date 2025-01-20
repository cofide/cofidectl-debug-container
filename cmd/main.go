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

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/logger"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

const (
	apiTimeout   = 5 * time.Second
	spiffeSocket = "unix:///spiffe-workload-api/spire-agent.sock"
	timeFormat   = time.RFC3339
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), apiTimeout)
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

	displayBundles(bundles)
	displaySVIDs(svids, bundles)
}

// displayBundles prints the trust bundles received from the workload API.
func displayBundles(bundles *x509bundle.Set) {
	if bundles == nil {
		fmt.Println("No trust bundles available")
		return
	}

	fmt.Println("Trust bundles received")
	if len(bundles.Bundles()) == 0 {
		fmt.Println("<none>")
		return
	}

	for _, b := range bundles.Bundles() {
		fmt.Printf("* %s\n", b.TrustDomain().IDString())
		printCertInfo(b.X509Authorities(), "    ")
	}
}

// displaySVIDs prints the SVIDs received from the SPIRE Workload API.
func displaySVIDs(svids []*x509svid.SVID, bundles *x509bundle.Set) {
	fmt.Println("\nSVIDs received")
	if len(svids) == 0 {
		fmt.Println("<none>")
		return
	}

	for _, s := range svids {
		fmt.Printf("* %s\n", s.ID.URL().String())
		printCertInfo(s.Certificates, "    ")
		if err := verifySVID(s, bundles); err != nil {
			fmt.Printf("    Verification failed: %v\n", err)
		} else {
			fmt.Printf("    SVID successfully verified against trust bundle\n")
		}
	}
}

// verifySVID verifies the SVID against the trust bundle.
func verifySVID(svid *x509svid.SVID, bundles *x509bundle.Set) error {
	if svid == nil {
		return fmt.Errorf("SVID is nil")
	}

	if bundles == nil {
		return fmt.Errorf("bundles is nil")
	}

	if len(svid.Certificates) == 0 {
		return fmt.Errorf("SVID has no certificates")
	}

	bundle, err := bundles.GetX509BundleForTrustDomain(svid.ID.TrustDomain())
	if err != nil {
		return fmt.Errorf("failed to get bundle for trust domain %q: %w", svid.ID.TrustDomain().IDString(), err)
	}
	if bundle == nil {
		return fmt.Errorf("no trust bundle found for trust domain %q", svid.ID.TrustDomain().IDString())
	}

	verifier := x509.NewCertPool()
	for _, ca := range bundle.X509Authorities() {
		verifier.AddCert(ca)
	}

	_, err = svid.Certificates[0].Verify(x509.VerifyOptions{
		Roots:         verifier,
		CurrentTime:   time.Now(),
		Intermediates: x509.NewCertPool(),
	})
	if err != nil {
		return fmt.Errorf("SVID verification failed: %w", err)
	}

	return nil
}

// printCertInfo prints information about a list of certificates.
func printCertInfo(certs []*x509.Certificate, prefix string) {
	for i, c := range certs {
		if c == nil {
			fmt.Printf("%sError: nil certificate\n", prefix)
			continue
		}

		fmt.Printf("%sCertificate %q\n", prefix, fingerprintCert(c))
		if c.IsCA {
			fmt.Printf("%sis a CA certificate\n", prefix)
		}

		fmt.Printf("%sValid from %q to %q\n", prefix, c.NotBefore.Format(timeFormat), c.NotAfter.Format(timeFormat))

		if c.Subject.String() != "" {
			fmt.Printf("%sSubject: %s\n", prefix, c.Subject.String())
		}

		if len(c.URIs) > 0 {
			uris := make([]string, 0, len(c.URIs))
			for _, uri := range c.URIs {
				uris = append(uris, uri.String())
			}
			fmt.Printf("%sURIs: %s\n", prefix, strings.Join(uris, ", "))
		}

		fmt.Printf("%sSignature algorithm: %s\n", prefix, c.SignatureAlgorithm.String())
		fmt.Printf("%sIssuer: %s\n", prefix, c.Issuer.String())

		if i < len(certs)-1 {
			fmt.Println()
		}
	}
}

// fingerprintCert returns the SHA-256 fingerprint of the certificate.
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
