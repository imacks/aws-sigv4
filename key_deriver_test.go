package sigv4

import (
	"bytes"
	"testing"
	"time"
)

func TestDerivedKeyCache(t *testing.T) {
	c := newDerivedKeyCache()
	c.nowFunc = func() time.Time {
		return time.Unix(0, 0)
	}
	if len(c.values) != 0 {
		t.Fatalf("expect empty cache")
	}

	tm := NewTime(time.Unix(0, 0))
	signKey := c.Get("AKIA1234567890", "SECRET", "dynamodb", "us-east-1", tm)
	if len(c.values) != 1 {
		t.Fatalf("expect 1 cache item")
	}
	cachedItem, ok := c.values["AKIA1234567890/"+tm.ShortTimeFormat()+"/us-east-1/dynamodb"]
	if !ok {
		t.Fatalf("item not cached")
	}
	if !bytes.Equal(cachedItem.Credential, signKey) {
		t.Fatalf("got wrong item from cache")
	}

	_, status := c.getFromCache("AKIA1234567890/"+tm.ShortTimeFormat()+"/us-east-1/dynamodb")
	if status != 0 {
		t.Fatalf("expect status 0 but got %d", status)
	}
}