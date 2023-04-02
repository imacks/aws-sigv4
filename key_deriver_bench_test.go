package sigv4

import (
	"testing"
	gotime "time"
)

func BenchmarkDeriveKey(b *testing.B) {
	b.ReportAllocs()

	t := NewTime(gotime.Now())
	for i := 0; i < b.N; i++ {
		deriveKey("SECRET", "dynamodb", "us-east-1", t)
	}
}

func BenchmarkDeriveKey_Cache(b *testing.B) {
	b.ReportAllocs()

	deriver := newKeyDeriver()
	t := NewTime(gotime.Now())
	for i := 0; i < b.N; i++ {
		deriver.DeriveKey("AKIA1234567890", "SECRET", "dynamodb", "us-east-1", t)
	}
}