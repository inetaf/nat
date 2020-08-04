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
			fn: func(_ []byte) []byte {
				return []byte{natpmp.Version, op, 0x00}
			},
			err: io.ErrUnexpectedEOF,
		},
		{
			name: "bad header version",
			fn: func(_ []byte) []byte {
				// Always expect version 0.
				return []byte{natpmp.Version + 1, op, 0x00, 0x00}
			},
			err: natpmp.ErrProtocol,
		},
		{
			name: "bad header op",
			fn: func(_ []byte) []byte {
				// Always expect a fixed response op.
				return []byte{natpmp.Version, op + 1, 0x00, 0x00}
			},
			err: natpmp.ErrProtocol,
		},
		{
			name: "short message",
			fn: func(_ []byte) []byte {
				return []byte{natpmp.Version, op, 0x00, 0x00, 0x00}
			},
			err: io.ErrUnexpectedEOF,
		},
		{
			name: "network failure",
			fn:   func(_ []byte) []byte { return resNetworkFailure },
			err:  natpmp.NetworkFailure,
		},
		{
			name: "success",
			fn:   func(_ []byte) []byte { return resOK },
			ext:  ext,
		},
		// In the retry tests, we simulate the first request being dropped so
		// the client must retry to receive a response.
		{
			name: "retry error",
			fn: func() serverFunc {
				var done bool
				return func(_ []byte) []byte {
					if !done {
						done = true
						return nil
					}

					return resNetworkFailure
				}
			}(),
			err: natpmp.NetworkFailure,
		},
		{
			name: "retry success",
			fn: func() serverFunc {
				var done bool
				return func(_ []byte) []byte {
					if !done {
						done = true
						return nil
					}

					return resOK
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
				fn = func(req []byte) []byte {
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

func TestClientMap(t *testing.T) {
	t.Parallel()

	const op = 128

	tests := []struct {
		name string
		fn   serverFunc
		req  natpmp.MapRequest
		res  *natpmp.MapResponse
		err  error
	}{
		{
			name: "bad protocol",
			req: natpmp.MapRequest{
				Protocol: natpmp.TCP + 1,
			},
			err: natpmp.ErrBadRequest,
		},
		{
			name: "bad internal port",
			req: natpmp.MapRequest{
				Protocol:     natpmp.UDP,
				InternalPort: 0,
			},
			err: natpmp.ErrBadRequest,
		},
		{
			name: "bad external port",
			req: natpmp.MapRequest{
				Protocol:              natpmp.UDP,
				InternalPort:          80,
				SuggestedExternalPort: -1,
			},
			err: natpmp.ErrBadRequest,
		},
		{
			name: "short message",
			fn: func(_ []byte) []byte {
				return []byte{natpmp.Version, op + uint8(natpmp.UDP), 0x00, 0x00, 0x00}
			},
			req: natpmp.MapRequest{
				Protocol:     natpmp.UDP,
				InternalPort: 80,
			},
			err: io.ErrUnexpectedEOF,
		},
		{
			name: "success",
			fn: func(req []byte) []byte {
				want := []byte{
					// Header.
					natpmp.Version, uint8(natpmp.UDP), 0x00, 0x00,
					// Ports.
					0x00, 80, 0x00, 80,
					// Lifetime.
					0x00, 0x00, 0x1c, 0x20,
				}

				if diff := cmp.Diff(want, req); diff != "" {
					panicf("unexpected request (-want +got):\n%s", diff)
				}

				return []byte{
					// Header.
					natpmp.Version, op + uint8(natpmp.UDP), 0x00, 0x00,
					// Since start of epoch.
					0x00, 0x00, 0x00, 60,
					// Ports.
					0x00, 80, 0x00, 80,
					// Lifetime.
					0x00, 0x00, 0x1c, 0x20,
				}
			},
			req: natpmp.MapRequest{
				Protocol:              natpmp.UDP,
				InternalPort:          80,
				SuggestedExternalPort: 80,
				RequestedLifetime:     2 * time.Hour,
			},
			res: &natpmp.MapResponse{
				SinceStartOfEpoch: 1 * time.Minute,
				InternalPort:      80,
				ExternalPort:      80,
				Lifetime:          2 * time.Hour,
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			c, done := testServer(t, tt.fn)
			defer done()

			ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
			defer cancel()

			res, err := c.Map(ctx, tt.req)
			if !errors.Is(err, tt.err) {
				t.Fatalf("unexpected error (-want +got):\n%s", cmp.Diff(tt.err, err))
			}

			if diff := cmp.Diff(tt.res, res); diff != "" {
				t.Fatalf("unexpected map response (-want +got):\n%s", diff)
			}
		})
	}
}

// A serverFunc is a function which can simulate a server's request/response
// lifecycle. A nil return value indicates that no response will be sent.
type serverFunc func(req []byte) (res []byte)

func testServer(t *testing.T, fn serverFunc) (*natpmp.Client, func()) {
	t.Helper()

	// Create a local UDP server listener which will invoke fn for each request
	// to generate responses until the returned done function is invoked and
	// the context is canceled.
	pc, err := net.ListenPacket("udp4", "localhost:0")
	if err != nil {
		t.Fatalf("failed to bind local UDP server listener: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		defer wg.Done()

		if fn == nil {
			// Nothing to do.
			return
		}

		// Read client input and continue to send responses until the context
		// is canceled.
		b := make([]byte, 256)
		for {
			n, addr, err := pc.ReadFrom(b)
			if err != nil {
				if ctx.Err() != nil {
					// Halted via context.
					return
				}

				panicf("failed to read from client: %v", err)
			}

			if res := fn(b[:n]); res != nil {
				if _, err := pc.WriteTo(res, addr); err != nil {
					panicf("failed to write to client: %v", err)
				}
			}
		}
	}()

	// Point the test client at our server.
	c, err := natpmp.Dial(pc.LocalAddr().String())
	if err != nil {
		t.Fatalf("failed to dial Client: %v", err)
	}

	return c, func() {
		// Unblock and halt the goroutine.
		cancel()
		_ = pc.SetReadDeadline(time.Unix(0, 1))

		wg.Wait()
		_ = pc.Close()
		_ = c.Close()
	}
}

func panicf(format string, a ...interface{}) {
	panic(fmt.Sprintf(format, a...))
}
