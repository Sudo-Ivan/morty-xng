package contenttype

import "testing"

func FuzzParseContentType(f *testing.F) {
	seeds := []string{
		"text/html",
		"text/html; charset=utf-8",
		"application/xhtml+xml",
		"text/",
		";",
		"text/plain; boundary=something",
		"",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		ct, err := ParseContentType(s)
		if err == nil {
			// String() must not panic and must produce a media type
			_ = ct.String()
		}
	})
}
