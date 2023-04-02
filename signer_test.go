package sigv4

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"reflect"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func buildRequest(serviceName, region, body string) (*http.Request, string) {
	reader := strings.NewReader(body)
	return buildRequestWithBodyReader(serviceName, region, reader)
}

func buildRequestWithBodyReader(serviceName, region string, body io.Reader) (*http.Request, string) {
	var bodyLen int

	type lenner interface {
		Len() int
	}
	if lr, ok := body.(lenner); ok {
		bodyLen = lr.Len()
	}

	endpoint := "https://" + serviceName + "." + region + ".amazonaws.com"
	req, _ := http.NewRequest("POST", endpoint, body)
	req.URL.Opaque = "//example.org/bucket/key-._~,!@#$%^&*()"
	req.Header.Set("X-Amz-Target", "prefix.Operation")
	req.Header.Set("Content-Type", "application/x-amz-json-1.0")

	if bodyLen > 0 {
		req.ContentLength = int64(bodyLen)
	}

	req.Header.Set("X-Amz-Meta-Other-Header", "some-value=!@#$%^&* (+)")
	req.Header.Add("X-Amz-Meta-Other-Header_With_Underscore", "some-value=!@#$%^&* (+)")
	req.Header.Add("X-amz-Meta-Other-Header_With_Underscore", "some-value=!@#$%^&* (+)")

	h := sha256.New()
	_, _ = io.Copy(h, body)
	payloadHash := hex.EncodeToString(h.Sum(nil))

	return req, payloadHash
}

func TestNew(t *testing.T) {
	req, payloadHash := buildRequest("dynamodb", "us-east-1", `{"foo":"bar"}`)
	req.Body = io.NopCloser(bytes.NewReader([]byte(`{"foo":"bar"}`)))
	origURL := req.URL.String()
	origHeaders := make(http.Header)
	for k, v := range req.Header {
		origHeaders[k] = v
	}

	signer, _ := New(
		WithCredential("AKID", "SECRET", "SESSION"),
		WithRegionService("us-east-1", "dynamodb"))
	err := signer.Sign(req, payloadHash, NewTime(time.Unix(0, 0)))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	t.Logf("hash %q", payloadHash)

	if actual := req.URL.String(); actual != origURL {
		t.Errorf("url has changed from %q to %q", origURL, actual)
	}

	for k, v := range req.Header {
		if _, ok := origHeaders[k]; ok {
			continue
		}
		switch k {
		case AmzDateKey:
			if len(v) != 1 {
				t.Errorf("wrong header value %q: %v", k, v)
			}
			if v[0] != "19700101T000000Z" {
				t.Errorf("expect header %q value == %q but got %q", k, "19700101T000000Z", v[0])
			}
		case AmzSecurityTokenKey:
			if len(v) != 1 {
				t.Errorf("wrong header value %q: %v", k, v)
			}
			if v[0] != "SESSION" {
				t.Errorf("expect header %q value == %q but got %q", k, "SESSION", v[0])
			}
		case authorizationHeader:
			if len(v) != 1 {
				t.Errorf("wrong header value %q: %v", k, v)
			}
			expect := `AWS4-HMAC-SHA256 Credential=AKID/19700101/us-east-1/dynamodb/aws4_request, SignedHeaders=content-length;content-type;host;x-amz-date;x-amz-meta-other-header;x-amz-meta-other-header_with_underscore;x-amz-security-token;x-amz-target, Signature=1fb32abd8e02925d6c100b2fb68f4210e01d36cce85d0215b44aa5abd86a7707`
			if v[0] != expect {
				t.Errorf("expect header %q value == %q but got %q", k, expect, v[0])
			}
		default:
			t.Logf("unexpected new header: %q = %v", k, v)
		}	
	}
	for k, v := range origHeaders {
		if _, ok := req.Header[k]; !ok {
			t.Errorf("removed header %q = %v", k, v)
		}
	}
}

func TestPresign_Request(t *testing.T) {
	req, payloadHash := buildRequest("dynamodb", "us-east-1", "{}")

	query := req.URL.Query()
	query.Set("X-Amz-Expires", "300")
	req.URL.RawQuery = query.Encode()

	//t.Logf("before: %v", req.Header)

	signer, _ := New(
		WithCredential("AKID", "SECRET", "SESSION"),
		WithRegionService("us-east-1", "dynamodb"))
	signed, headers, err := signer.Presign(req, payloadHash, NewTime(time.Unix(0, 0)))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expectedDate := "19700101T000000Z"
	expectedHeaders := "content-length;content-type;host;x-amz-meta-other-header;x-amz-meta-other-header_with_underscore"
	expectedSig := "122f0b9e091e4ba84286097e2b3404a1f1f4c4aad479adda95b7dff0ccbe5581"
	expectedCred := "AKID/19700101/us-east-1/dynamodb/aws4_request"
	expectedTarget := "prefix.Operation"

	q := signed.Query()

	if e, a := expectedSig, q.Get("X-Amz-Signature"); e != a {
		t.Errorf("expect %v but got %v", e, a)
	}
	if e, a := expectedCred, q.Get("X-Amz-Credential"); e != a {
		t.Errorf("expect %v but got %v", e, a)
	}
	if e, a := expectedHeaders, q.Get("X-Amz-SignedHeaders"); e != a {
		t.Errorf("expect %v but got %v", e, a)
	}
	if e, a := expectedDate, q.Get("X-Amz-Date"); e != a {
		t.Errorf("expect %v but got %v", e, a)
	}
	if a := q.Get("X-Amz-Meta-Other-Header"); len(a) != 0 {
		t.Errorf("expect %v to be empty", a)
	}
	if e, a := expectedTarget, q.Get("X-Amz-Target"); e != a {
		t.Errorf("expect %v but got %v", e, a)
	}

	for _, h := range strings.Split(expectedHeaders, ";") {
		v := headers.Get(h)
		if len(v) == 0 {
			t.Errorf("expect %v to be present in header map", h)
		}
	}
}

func TestPresign_BodyWithArrayRequest(t *testing.T) {
	//t.Skip()
	req, payloadHash := buildRequest("dynamodb", "us-east-1", "{}")
	req.URL.RawQuery = "Foo=z&Foo=o&Foo=m&Foo=a"

	query := req.URL.Query()
	query.Set("X-Amz-Expires", "300")
	req.URL.RawQuery = query.Encode()

	signer, _ := New(
		WithCredential("AKID", "SECRET", "SESSION"),
		WithRegionService("us-east-1", "dynamodb"))
	signed, headers, err := signer.Presign(req, payloadHash, NewTime(time.Unix(0, 0)))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	q := signed.Query()

	expectedDate := "19700101T000000Z"
	expectedHeaders := "content-length;content-type;host;x-amz-meta-other-header;x-amz-meta-other-header_with_underscore"
	expectedSig := "e3ac55addee8711b76c6d608d762cff285fe8b627a057f8b5ec9268cf82c08b1"
	expectedCred := "AKID/19700101/us-east-1/dynamodb/aws4_request"
	expectedTarget := "prefix.Operation"

	if e, a := expectedSig, q.Get("X-Amz-Signature"); e != a {
		t.Errorf("expect %v but got %v", e, a)
	}
	if e, a := expectedCred, q.Get("X-Amz-Credential"); e != a {
		t.Errorf("expect %v but got %v", e, a)
	}
	if e, a := expectedHeaders, q.Get("X-Amz-SignedHeaders"); e != a {
		t.Errorf("expect %v but got %v", e, a)
	}
	if e, a := expectedDate, q.Get("X-Amz-Date"); e != a {
		t.Errorf("expect %v, got %v", e, a)
	}
	if a := q.Get("X-Amz-Meta-Other-Header"); len(a) != 0 {
		t.Errorf("expect %v to be empty", a)
	}
	if e, a := expectedTarget, q.Get("X-Amz-Target"); e != a {
		t.Errorf("expect %v but got %v", e, a)
	}

	for _, h := range strings.Split(expectedHeaders, ";") {
		v := headers.Get(h)
		if len(v) == 0 {
			t.Errorf("expect %v to be present in header map", h)
		}
	}
}

func TestHTTPSigner_Request(t *testing.T) {
	req, body := buildRequest("dynamodb", "us-east-1", "{}")
	signer, _ := New(
		WithCredential("AKID", "SECRET", "SESSION"),
		WithRegionService("us-east-1", "dynamodb"))
	err := signer.Sign(req, body, NewTime(time.Unix(0, 0)))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expectedDate := "19700101T000000Z"
	expectedSig := "AWS4-HMAC-SHA256 Credential=AKID/19700101/us-east-1/dynamodb/aws4_request, SignedHeaders=content-length;content-type;host;x-amz-date;x-amz-meta-other-header;x-amz-meta-other-header_with_underscore;x-amz-security-token;x-amz-target, Signature=a518299330494908a70222cec6899f6f32f297f8595f6df1776d998936652ad9"

	q := req.Header
	if e, a := expectedSig, q.Get("Authorization"); e != a {
		t.Errorf("expect %v but got %v", e, a)
	}
	if e, a := expectedDate, q.Get("X-Amz-Date"); e != a {
		t.Errorf("expect %v but got %v", e, a)
	}
}

func TestBuildCanonicalRequest(t *testing.T) {
	const rawQuery = "Foo=z&Foo=o&Foo=m&Foo=a"
	req, _ := buildRequest("dynamodb", "us-east-1", "{}")
	req.URL.RawQuery = rawQuery

	signer, _ := New(
		WithCredential("AKID", "SECRET", "SESSION"),
		WithRegionService("us-east-1", "dynamodb"))

	err := signer.Sign(req, "", NewTime(time.Now()))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Foo=a&Foo=m&Foo=o&Foo=z
	expected := "https://example.org/bucket/key-._~,!@#$%^&*()?"+rawQuery
	if e, a := expected, req.URL.String(); e != a {
		t.Errorf("expect %v but got %v", e, a)
	}
}

func TestSigner_SignHTTP_NoReplaceRequestBody(t *testing.T) {
	req, bodyHash := buildRequest("dynamodb", "us-east-1", "{}")
	req.Body = io.NopCloser(bytes.NewReader([]byte{}))

	signer, _ := New(
		WithCredential("AKID", "SECRET", "SESSION"),
		WithRegionService("us-east-1", "dynamodb"))

	origBody := req.Body

	err := signer.Sign(req, bodyHash, NewTime(time.Now()))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if req.Body != origBody {
		t.Errorf("expect request body to not change")
	}
}

func TestRequestHost(t *testing.T) {
	req, payloadHash := buildRequest("dynamodb", "us-east-1", "{}")
	req.URL.RawQuery = "Foo=z&Foo=o&Foo=m&Foo=a"
	req.Host = "myhost"

	query := req.URL.Query()
	query.Set("X-Amz-Expires", "5")
	req.URL.RawQuery = query.Encode()

	req2 := req.Clone(req.Context())
	//t.Logf("req before: %s", req.URL)
	//t.Logf("req before2: %s", req.Header)

	signer, _ := New(
		WithCredential("AKID", "SECRET", "SESSION"),
		WithRegionService("us-east-1", "dynamodb"))
	
	signer.Sign(req2, payloadHash, NewTime(time.Now()))
	//t.Logf("canonical string: %s", canon)
	//t.Logf("str to sign: %s", strToSign)
	//t.Logf("signed map: %s", signed)

	for k, v := range req.Header {
		v2, ok := req2.Header[k]
		if !ok {
			t.Fatalf("missing header %q in signed request", k)
		}
		if !reflect.DeepEqual(v, v2) {
			t.Fatalf("expect header %q in signed request value == %v but got %v", k, v, v2)
		}
	}

	for k, v := range req2.Header {
		v2, ok := req.Header[k]
		if k == authorizationHeader || k == AmzDateKey || k == AmzSecurityTokenKey {
			if ok {
				t.Fatalf("does not expect header %q in original request", k)
			}
			continue
		}

		if !ok {
			t.Fatalf("missing header %q", k)
		}
		if !reflect.DeepEqual(v, v2) {
			t.Fatalf("invalid header %q value: %v", k, v)
		}
	}

	if v := req2.Header.Get("Authorization"); !strings.Contains(v, ";host;") {
		t.Fatalf("invalid authorization header value: %s", v)
	}
}

func TestHTTPSigner_buildCanonicalHeadersContentLengthPresent(t *testing.T) {
	body := `{"description": "this is a test"}`
	req, _ := buildRequest("dynamodb", "us-east-1", body)
	req.URL.RawQuery = "Foo=z&Foo=o&Foo=m&Foo=a"
	req.Host = "myhost"

	contentLength := fmt.Sprintf("%d", len([]byte(body)))
	req.Header.Add("Content-Length", contentLength)

	query := req.URL.Query()
	query.Set("X-Amz-Expires", "5")
	req.URL.RawQuery = query.Encode()

	hasher := &debugHasher{buf: []byte{}}
	canonicalRequestHash(hasher, req, req.Header, req.URL.Query(), req.Host,
		EmptyStringSHA256, true, false, nil)

	actual := string(hasher.buf)
	if !strings.Contains(actual, "content-length:"+contentLength+"\n") {
		t.Errorf("invalid canonical header content-length")
	}
}

func TestHTTPSigner_buildCanonicalHeaders(t *testing.T) {
	serviceName := "mockAPI"
	region := "mock-region"
	endpoint := "https://" + serviceName + "." + region + ".amazonaws.com"

	req, err := http.NewRequest("POST", endpoint, nil)
	if err != nil {
		t.Fatalf("failed to create request, %v", err)
	}

	req.Header.Set("FooInnerSpace", "   inner      space    ")
	req.Header.Set("FooLeadingSpace", "    leading-space")
	req.Header.Add("FooMultipleSpace", "no-space")
	req.Header.Add("FooMultipleSpace", "\ttab-space")
	req.Header.Add("FooMultipleSpace", "trailing-space    ")
	req.Header.Set("FooNoSpace", "no-space")
	req.Header.Set("FooTabSpace", "\ttab-space\t")
	req.Header.Set("FooTrailingSpace", "trailing-space    ")
	req.Header.Set("FooWrappedSpace", "   wrapped-space    ")
	req.Header.Set("x-amz-date", "20211020T124200Z")

	hasher := &debugHasher{buf: []byte{}}
	canonicalRequestHash(hasher, req, req.Header, req.URL.Query(), req.Host,
		EmptyStringSHA256, true, false, nil)
	expectCanonicalString := strings.Join([]string{
		`POST`,
		`/`,
		``,
		`fooinnerspace:inner space`,
		`fooleadingspace:leading-space`,
		`foomultiplespace:no-space,tab-space,trailing-space`,
		`foonospace:no-space`,
		`footabspace:tab-space`,
		`footrailingspace:trailing-space`,
		`foowrappedspace:wrapped-space`,
		`host:mockAPI.mock-region.amazonaws.com`,
		`x-amz-date:20211020T124200Z`,
		``,
		`fooinnerspace;fooleadingspace;foomultiplespace;foonospace;footabspace;footrailingspace;foowrappedspace;host;x-amz-date`,
		`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`,
	}, "\n")

	actual := string(hasher.buf)
	if expectCanonicalString != actual {
		t.Errorf("expect %q but got %q", expectCanonicalString, actual)
	}
}
