package natpmp_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/net/nettest"
	"inet.af/nat/natpmp"
)

func TestClientExternalAddress(t *testing.T) {
	t.Parallel()

	// Fixed data structures reused throughout tests.
	const op = 128

	var (
		resNetworkFailure = []byte{
			// An error header with no body.
			natpmp.Version, op, 0x00, uint8(natpmp.NetworkFailure),
		}

		resOK = []byte{
			// Success response.
			natpmp.Version, op, 0x00, 0x00,
			// Duration since epoch.
			0x00, 0x00, 0x01, 0xff,
			// External IP address.
			192, 0, 2, 1,
		}

		ext = &natpmp.ExternalAddress{
			SinceStartOfEpoch: 8*time.Minute + 31*time.Second,
			ExternalIP:        net.IPv4(192, 0, 2, 1),
		}
	)

	tests := []struct {
		name string
		fn   serverFunc
		ext  *natpmp.ExternalAddress
		err  error
	}{
		{
			name: "context deadline",
			err:  context.DeadlineExceeded,
		},
		{
			name: "short header",
			fn: func(_ []byte) ([]byte, bool) {
				return []byte{natpmp.Version, op, 0x00}, true
			},
			err: io.ErrUnexpectedEOF,
		},
		{
			name: "bad header version",
			fn: func(_ []byte) ([]byte, bool) {
				// Always expect version 0.
				return []byte{natpmp.Version + 1, op, 0x00, 0x00}, true
			},
			err: natpmp.ErrProtocol,
		},
		{
			name: "bad header op",
			fn: func(_ []byte) ([]byte, bool) {
				// Always expect a fixed response op.
				return []byte{natpmp.Version, op + 1, 0x00, 0x00}, true
			},
			err: natpmp.ErrProtocol,
		},
		{
			name: "short message",
			fn: func(_ []byte) ([]byte, bool) {
				return []byte{natpmp.Version, op, 0x00, 0x00, 0x00}, true
			},
			err: io.ErrUnexpectedEOF,
		},
		{
			name: "network failure",
			fn: func(_ []byte) ([]byte, bool) {
				return resNetworkFailure, true
			},
			err: natpmp.NetworkFailure,
		},
		{
			name: "success",
			fn: func(req []byte) ([]byte, bool) {
				return resOK, true
			},
			ext: ext,
		},
		// In the retry tests, we simulate the first request being dropped so
		// the client must retry to receive a response.
		{
			name: "retry error",
			fn: func() serverFunc {
				var done bool
				return func(_ []byte) ([]byte, bool) {
					if !done {
						done = true
						return nil, false
					}

					return resNetworkFailure, true
				}
			}(),
			err: natpmp.NetworkFailure,
		},
		{
			name: "retry success",
			fn: func() serverFunc {
				var done bool
				return func(_ []byte) ([]byte, bool) {
					if !done {
						done = true
						return nil, false
					}

					return resOK, true
				}
			}(),
			ext: ext,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var fn serverFunc
			if tt.fn != nil {
				fn = func(req []byte) ([]byte, bool) {
					// Each request is fixed.
					if diff := cmp.Diff([]byte{natpmp.Version, 0x00}, req); diff != "" {
						panicf("unexpected request (-want +got):\n%s", diff)
					}

					return tt.fn(req)
				}
			}

			c, done := testServer(t, fn)
			defer done()

			ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
			defer cancel()

			ext, _, err := c.ExternalAddress(ctx)
			if !errors.Is(err, tt.err) {
				t.Fatalf("unexpected error (-want +got):\n%s", cmp.Diff(tt.err, err))
			}

			if diff := cmp.Diff(tt.ext, ext); diff != "" {
				t.Fatalf("unexpected external address (-want +got):\n%s", diff)
			}
		})
	}
}

// A serverFunc is a function which can simulate a server's request/response
// lifecycle and eventually finish the serving loop.
type serverFunc func(req []byte) (res []byte, done bool)

func testServer(t *testing.T, fn serverFunc) (*natpmp.Client, func()) {
	t.Helper()

	pc, err := nettest.NewLocalPacketListener("udp4")
	if err != nil {
		t.Fatalf("failed to bind local UDP server listener: %v", err)
	}

	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		defer wg.Done()

		if fn == nil {
			// Nothing to do.
			return
		}

		// Read client input and continue to send responses until the serverFunc
		// reports done.
		b := make([]byte, 256)
		for {
			n, addr, err := pc.ReadFrom(b)
			if err != nil {
				panicf("failed to read from client: %v", err)
			}

			res, done := fn(b[:n])

			if res != nil {
				if _, err := pc.WriteTo(res, addr); err != nil {
					panicf("failed to write to client: %v", err)
				}
			}

			if done {
				return
			}
		}
	}()

	// Point the test client at our server.
	c, err := natpmp.Dial(pc.LocalAddr().String())
	if err != nil {
		t.Fatalf("failed to dial Client: %v", err)
	}

	return c, func() {
		wg.Wait()
		_ = pc.Close()
		_ = c.Close()
	}
}

func panicf(format string, a ...interface{}) {
	panic(fmt.Sprintf(format, a...))
}
