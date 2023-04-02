package sigv4_test

import (
	"fmt"
	"net/http"
	"time"

	"code.lizoc.com/webber/webber/awssigv4/aws-sigv4"
)

func ExampleHTTPSigner_Sign() {
	req, _ := http.NewRequest("POST", "https://dynamodb.us-east-1.amazonaws.com", nil)

	signer, err := sigv4.New(
		sigv4.WithCredential("AKIA0123456789", "MY_SECRET", ""),
		sigv4.WithRegionService("us-east-1", "dynamodb"))
	if err != nil {
		panic(err)
	}
	// Sign will populate req.Header["Authorization"] with signature.
	// Change time.Unix(0, 0) to time.Now() before use.
	err = signer.Sign(req, sigv4.EmptyStringSHA256, sigv4.NewTime(time.Unix(0, 0)))
	if err != nil {
		panic(err)
	}

	fmt.Printf(req.Header["Authorization"][0])

	// Output:
	// AWS4-HMAC-SHA256 Credential=AKIA0123456789/19700101/us-east-1/dynamodb/aws4_request, SignedHeaders=host;x-amz-date, Signature=97afaccd6bb80fd0b79089a895eba5097231dfd469ad60c277e68c66ff80cae9
}

func ExampleHTTPSigner_Presign() {
	req, _ := http.NewRequest("POST", "https://dynamodb.us-east-1.amazonaws.com", nil)

	signer, err := sigv4.New(
		sigv4.WithCredential("AKIA0123456789", "MY_SECRET", ""),
		sigv4.WithRegionService("us-east-1", "dynamodb"))
	if err != nil {
		panic(err)
	}
	// Presign does not mutate req like Sign does. Instead, it returns a *url.URL 
	// and http.Header. You can recreate a request with the same url and header 
	// content and be authenticated.
	u, headers, err := signer.Presign(req, sigv4.EmptyStringSHA256, sigv4.NewTime(time.Unix(0, 0)))
	if err != nil {
		panic(err)
	}

	fmt.Printf("%s\n", u.String())
	fmt.Printf("%v", headers)

	// Output:
	// https://dynamodb.us-east-1.amazonaws.com?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIA0123456789%2F19700101%2Fus-east-1%2Fdynamodb%2Faws4_request&X-Amz-Date=19700101T000000Z&X-Amz-Signature=45f6eb538ffb523d8a44616f10275af717bc63a23320f7a37382c30d151e59a4&X-Amz-SignedHeaders=host
	// map[Host:[dynamodb.us-east-1.amazonaws.com]]
}