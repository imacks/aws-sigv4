/*
Package sigv4 implements AWS Signature Version 4 (sigv4) signer. See authoritative documentation at https://docs.aws.amazon.com/IAM/latest/UserGuide/signing-elements.html 
for details.

The sigv4 algorithm is briefly described here.

Step 1: make a canonical request string in the format `<METHOD>\n<URI>\n<QUERY>\n<HEADERS>\n<SIGNED_HEADERS>\n<PAYLOAD_HASH>`.

    - `METHOD`: HTTP method in upper case.
    - `URI`: the URL path component (between host and query), such as `/foo/bar`. It must be URI-encoded. Use `/` if this 
      component is empty.
    - `QUERY`: the URL query component (after the first `?`), such as `Foo=A&Bar=B`. For each key-value pair, reserved 
      characters (including space) in both name and value must be percent-encoded. If value is empty, it should end with 
      the `=` character, such as `Foo=`. Lastly, sort by key name. If there are multiple key-value pairs with the same key 
      name, they are sorted by their values. Use an empty string if there is no query component.
    - `HEADERS`: for each header in request that should be protected by the signature, its name and value, delimited by 
      newline (`\n`). Header names must be in lower-case and sorted. Values are separated from its header name by `:`. 
      Multiple values must be comma separated, with leading and trailing spaces removed. Multiple spaces must be replaced 
      with single space. The `host` header (or `:authority` if HTTP/2) must be included. If the request contains any 
      header with `x-amz-` prefix, they must be included as well. Do not include "authorization" or "x-amzn-trace-id". 
      All other headers are optional.
    - `SIGNED_HEADERS`: semi-colon (`;`) delimited list of header names in `HEADERS`. Like `HEADERS`, it must be sorted 
      and in lower-case.
    - `PAYLOAD_HASH`: the value of `hex(sha256(BODY))`, where `BODY` is HTTP request body content. If HTTP request body 
      is empty, use the hash value of an empty string.

Step 2: calculate `hex(sha256(CANON_REQ_STR))`, where `CANON_REQ_STR` is result of step 1.

Step 3: calculate string to sign: `<ALGO>\n<TIMESTAMP>\n<CRED_SCOPE>\n<HASH>`, where:

    - `ALGO`: hardcoded `AWS4-HMAC-SHA256`
    - `TIMESTAMP`: ISO8601 format time
    - `CRED_SCOPE`: `<YYYYMMDD>/<region>/<service>/aws4_request`, where `<YYYYMMDD>` is date portion of `TIMESTAMP`
    - `HASH`: value from step 2

Step 4: calculate signature `<sig>` per pseudo code here:

```
    // Secret is user secret key
    // Date is YYYYMMDD date from CRED_SCOPE in step 3
    hDate = hmacsha256("AWS4"+Secret, Date)
    // region and service are the same values in CRED_SCOPE
    hRegion = hmacsha256(hDate, Region)
    hService = hmacsha256(hRegion, Service)
    hSig = hmacsha256(hService, "aws4_request")

	// StringToSign is value from step 3
    // sig is the final result for this step
    sig = hex(hmacsha256(hSig, StringToSign))
```

Step 5: *either* add signature to request header or query string:

    - Header: add header `Authorization: AWS4-HMAC-SHA256 Credential=<ACCESS_ID>/<CRED_SCOPE>, SignedHeaders=<SIGNED_HEADERS>, Signature=<SIG>`
    - Query string: add these query parameters:
      - `X-Amz-Algorithm=AWS4-HMAC-SHA256`
      - `X-Amz-Credential=<ACCESS_ID>/<CRED_SCOPE>`
      - `X-Amz-Date=<TIMESTAMP>`
      - `X-Amz-SignedHeaders=<SIGNED_HEADERS>`
      - `X-Amz-Signature=<SIG>`
*/
package sigv4
