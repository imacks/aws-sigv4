package sigv4

import (
	"testing"
	"time"
)

func BenchmarkHTTPSigner_Sign(b *testing.B) {
	b.ReportAllocs()

	signer, err := New(WithCredential("AKID", "SECRET", "SESSION"),
		WithRegionService("us-east-1", "dynamodb"))
	if err != nil {
		b.Fatalf("unexpected error: %v", err)
	}

	req, bodyHash := buildRequest("dynamodb", "us-east-1", "{}")
	t := NewTime(time.Now())
	for i := 0; i < b.N; i++ {
		signer.Sign(req, bodyHash, t)
	}
}

func BenchmarkHTTPSigner_Presign(b *testing.B) {
	b.ReportAllocs()

	signer, err := New(WithCredential("AKID", "SECRET", "SESSION"),
		WithRegionService("us-east-1", "dynamodb"))
	if err != nil {
		b.Fatalf("unexpected error: %v", err)
	}

	req, bodyHash := buildRequest("dynamodb", "us-east-1", "{}")
	query := req.URL.Query()
	query.Set("X-Amz-Expires", "5")
	req.URL.RawQuery = query.Encode()

	t := NewTime(time.Now())
	for i := 0; i < b.N; i++ {
		signer.Presign(req, bodyHash, t)
	}
}
