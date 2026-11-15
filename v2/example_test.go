package dane_test

import (
	"context"
	"crypto/x509"
	"fmt"
	"time"

	dane "github.com/shuque/dane/v2"
)

// Example_client shows how a server authenticates a TLS client: look up
// the TLSA records at the ClientName, then verify the presented chain.
// It has no Output line, so it is compiled but not run.
func Example_client() {
	var chain []*x509.Certificate // peer certificates from the TLS handshake
	clientName := "_smtp._client.mta1.example.com"

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	res := dane.NewResolver("127.0.0.1:53") // trusted validating resolver
	rrset, err := res.LookupTLSA(ctx, clientName)
	if err != nil {
		fmt.Println("lookup failed:", err) // errors.Is(err, dane.ErrInsecure) etc.
		return
	}

	result, err := dane.Verify(chain, rrset, dane.VerifyOptions{
		Role: dane.RoleClient,
		Name: clientName,
	})
	if err != nil {
		fmt.Println("client not authenticated:", err)
		return
	}
	fmt.Println("authenticated by:", result.Matched.Record)
}
