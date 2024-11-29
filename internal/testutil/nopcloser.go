package testutil

import (
	"io"
)

// readSeekNopCloser is an io.Reader that does nothing on Close, and
// seeks to the beginning of the stream on Seek.
// It is an extension of io.NopCloser that also implements io.Seeker.
type readSeekNopCloser struct {
	io.ReadSeeker
}

// Close does nothing.
func (readSeekNopCloser) Close() error { return nil }

func ReadSeekNopCloser(r io.ReadSeeker) io.ReadSeekCloser {
	return readSeekNopCloser{r}
}
