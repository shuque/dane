package dane

import (
	"context"
	"net"
	"net/http"
	"strconv"
	"strings"
)

// GetHttpClient returns a net/http Client structure configured to perform
// DANE TLS authentication of the HTTPS server. If the argument pkixfallback
// is set to true, then PKIX authentication will be attempted if the server
// does not have any published secure DANE TLSA records.
func GetHttpClient(pkixfallback bool) http.Client {

	t := &http.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			tmp := strings.SplitN(addr, ":", 2)
			hostname := tmp[0]
			port, _ := strconv.Atoi(tmp[1])
			conn, _, err := ConnectByNameAsync2(hostname, port, pkixfallback)
			return conn, err
		},
	}
	return http.Client{Transport: t}
}
