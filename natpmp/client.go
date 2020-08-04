package natpmp

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// Version is the expected protocol version for NAT-PMP.
const Version = 0

var (
	// ErrBadRequest indicates an invalid parameter in a Client's request.
	ErrBadRequest = errors.New("natpmp: bad request")

	// ErrProtocol indicates that a NAT gateway returned a response that violates
	// the NAT-PMP protocol.
	ErrProtocol = errors.New("natpmp: protocol error")
)

// An Error is a NAT-PMP protocol result code which indicates that an operation
// has failed.
type Error int

// Possible Errors as defined in RFC 6886, section 3.5.
const (
	// UnsupportedVersion indicates an unexpected NAT-PMP/PCP protocol version
	// was used to contact a NAT gateway.
	UnsupportedVersion Error = 1

	// NotAuthorized indicates that the NAT gateway supports mapping but the
	// mapping functionality is administratively disabled.
	NotAuthorized Error = 2

	// NetworkFailure indicates that the NAT gateway has not obtained a DHCP
	// lease and thus cannot provide an external IPv4 address.
	NetworkFailure Error = 3

	// OutOfResources indicates that the NAT gateway cannot create any more
	// mappings at this time.
	OutOfResources Error = 4

	// UnsupportedOpcode indicates that the NAT gateway does not recognize the
	// requested operation.
	UnsupportedOpcode Error = 5

	// success indicates a successful request. Although success is technically a
	// result code, we don't expose it directly to the user because a successful
	// operation returns nil error.
	success Error = 0
)

// Error implements error.
func (e Error) Error() string {
	return fmt.Sprintf("natpmp: result %d: %s", e, e.String())
}

// A Client is a NAT-PMP client which can communicate with a NAT gateway.
type Client struct {
	// The UDP socket and address used to communicate with a NAT gateway.
	mu      sync.Mutex
	pc      net.PacketConn
	gateway net.Addr
}

// Dial creates a Client which communicates with the NAT gateway specified by
// addr.
func Dial(addr string) (*Client, error) {
	gateway, err := net.ResolveUDPAddr("udp4", addr)
	if err != nil {
		return nil, err
	}

	pc, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		return nil, err
	}

	// TODO(mdlayher): create a second listener on 224.0.0.1:5350 to listen
	// to multicasts from a NAT gateway.

	return &Client{
		pc:      pc,
		gateway: gateway,
	}, nil
}

// Close closes the Client's underlying connection.
func (c *Client) Close() error {
	return c.pc.Close()
}

// An ExternalAddress is the result of a Client's ExternalAddress method.
type ExternalAddress struct {
	SinceStartOfEpoch time.Duration
	ExternalIP        net.IP
}

// ExternalAddress returns external IP address information from a NAT gateway,
// as described in RFC 4886, section 3.2.
func (c *Client) ExternalAddress(ctx context.Context) (*ExternalAddress, net.Addr, error) {
	// This messages's request is always fixed, and the response always has a
	// fixed size and response opcode. See:
	// https://tools.ietf.org/html/rfc6886#section-3.2.
	const (
		size  = 12
		reqOp = 0x00
		resOp = 128
	)

	b := make([]byte, size)
	n, addr, err := c.request(ctx, []byte{Version, reqOp}, b, resOp)
	if err != nil {
		return nil, nil, err
	}

	if n != size {
		return nil, nil, io.ErrUnexpectedEOF
	}

	// We allocated a buffer internally, no need to produce a copy of the data
	// for the output IP address.
	return &ExternalAddress{
		SinceStartOfEpoch: time.Duration(binary.BigEndian.Uint32(b[4:8])) * time.Second,
		ExternalIP:        b[8:12],
	}, addr, nil
}

// Map creates an external port mapping with a NAT gateway, as described in
// RFC 4886, section 3.3. See the documentation of MapRequest for the necessary
// parameters.
func (c *Client) Map(ctx context.Context, mr MapRequest) (*MapResponse, error) {
	mb, err := mr.marshal()
	if err != nil {
		// Wrap with bad request sentinel for ease of error checking.
		return nil, fmt.Errorf("%w: %v", ErrBadRequest, err)
	}

	// The response has a fixed size and expected base opcode. The protocol
	// value is added to get the expected response opcode. See:
	// https://tools.ietf.org/html/rfc6886#section-3.3.
	const (
		size  = 16
		resOp = 128
	)

	b := make([]byte, size)
	n, _, err := c.request(ctx, mb, b, resOp+int(mr.Protocol))
	if err != nil {
		return nil, err
	}

	if n != size {
		return nil, io.ErrUnexpectedEOF
	}

	// Skip first 4 header bytes and parse the remainder of the message.
	return &MapResponse{
		SinceStartOfEpoch: time.Duration(binary.BigEndian.Uint32(b[4:8])) * time.Second,
		InternalPort:      int(binary.BigEndian.Uint16(b[8:10])),
		ExternalPort:      int(binary.BigEndian.Uint16(b[10:12])),
		Lifetime:          time.Duration(binary.BigEndian.Uint32(b[12:16])) * time.Second,
	}, nil
}

// request serializes and implements backoff/retry for NAT-PMP request/response
// interactions, as recommended by
// https://tools.ietf.org/html/rfc6886#section-3.1.
func (c *Client) request(ctx context.Context, req, res []byte, resOp int) (int, net.Addr, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	var wg sync.WaitGroup
	wg.Add(1)
	defer wg.Wait()

	// Either wait for the parent context to be canceled or for this function to
	// complete, and then unblock any outstanding reads and return control to
	// the caller.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	go func() {
		defer wg.Done()
		<-ctx.Done()
		// Only unblock reads because writes won't block, and SetDeadline will
		// prevent future writes due to I/O timeout.
		_ = c.pc.SetReadDeadline(time.Unix(0, 1))
	}()

	// Start with a 250ms delay on timeout error and double it up to 9 times
	// per the RFC.
	var nerr net.Error
	timeout := 250 * time.Millisecond
	for i := 0; i < 9; i++ {
		if err := ctx.Err(); err != nil {
			return 0, nil, err
		}

		// Send a request to the gateway and await its response or a timeout.
		if err := c.pc.SetReadDeadline(time.Now().Add(timeout)); err != nil {
			return 0, nil, err
		}

		if _, err := c.pc.WriteTo(req, c.gateway); err != nil {
			return 0, nil, err
		}

		n, addr, err := c.pc.ReadFrom(res)
		switch {
		case errors.As(err, &nerr) && nerr.Timeout():
			// Was this timeout produced by context cancelation? If so, return
			// immediately. If not, double the timeout and retry.
			if err := ctx.Err(); err != nil {
				return 0, nil, err
			}

			timeout *= 2
		case err == nil:
			// Successful read, parse the header and verify the expected
			// response opcode.
			if err := checkHeader(res[:n], resOp); err != nil {
				return n, addr, err
			}

			return n, addr, nil
		default:
			// Unexpected error.
			return n, addr, err
		}
	}

	// TODO(mdlayher): implement net.Error.Timeout?
	return 0, nil, errors.New("natpmp: exhausted retries")
}

// checkHeader validates the header bytes of a NAT-PMP response.
func checkHeader(b []byte, op int) error {
	if len(b) < 4 {
		return io.ErrUnexpectedEOF
	}

	if b[0] != Version {
		return fmt.Errorf("natpmp: unexpected protocol version: %d: %w", b[0], ErrProtocol)
	}
	if int(b[1]) != op {
		return fmt.Errorf("natpmp: unexpected response opcode: %d != %d: %w", b[1], op, ErrProtocol)
	}

	// Any non-zero value is an error and is wrapped in our Error type.
	if err := Error(binary.BigEndian.Uint16(b[2:4])); err != success {
		return err
	}

	return nil
}
