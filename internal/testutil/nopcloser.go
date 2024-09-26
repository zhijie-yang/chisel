package testutil

import (
	"io"
)

// NopSeekCloser is an io.Reader that does nothing on Close, and
// seeks to the beginning of the stream on Seek.
// It is an extension of io.NopCloser that also implements io.Seeker.
type readSeekerNopCloser struct {
	io.ReadSeeker
}

// Close does nothing.
func (readSeekerNopCloser) Close() error { return nil }

func ReadSeekerNopCloser(r io.ReadSeeker) io.ReadSeekCloser {
	return readSeekerNopCloser{r}
}
