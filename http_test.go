package dane

/*
 * Note: these test routines may not work unless you adapt this file
 * to use validating DNS resolvers and appropriately configured DANE TLS
 * servers you have access to.
 */

import (
	"fmt"
	"io"
	"net/http"
	"testing"
)

func TestGetHttpClient(t *testing.T) {

	defer fmt.Println()

	var urlstring = "https://www.example.com/"

	fmt.Printf("## HTTPCLIENT: %s\n", urlstring)

	httpclient := GetHttpClient(true)
	request, err := http.NewRequest(http.MethodGet, urlstring, nil)
	if err != nil {
		t.Fatalf("http.NewRequest: %s\n", err.Error())
	}

	response, err := httpclient.Do(request)
	if err != nil {
		t.Fatalf("http.Do: %s\n", err.Error())
	}
	if response.Body != nil {
		defer response.Body.Close()
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("Reading HTTP response body: %s\n", err.Error())
	}
	_ = body
	fmt.Printf("GetHttpClient: Success connecting to %s\n", urlstring)
}
