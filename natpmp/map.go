package natpmp

import (
	"encoding/binary"
	"fmt"
	"math"
	"time"
)

// A Protocol determines if a TCP or UDP port mapping should be created with a
// NAT gateway.
type Protocol int

// Possible Protocol values.
const (
	UDP Protocol = 1
	TCP Protocol = 2
)

// A MapRequest is used to create an external port mapping using a NAT gateway.
type MapRequest struct {
	// Protocol specifies whether a TCP or UDP port mapping should be created.
	Protocol Protocol

	// InternalPort specifies the port of a service running on this host which
	// requires an external mapping via a NAT gateway.
	InternalPort int

	// SuggestedExternalPort optionally specifies a suggested external port for
	// the NAT gateway to map to the InternalPort in this request. If zero, the
	// gateway will allocate a high-number ephemeral port of its choosing.
	//
	// Note that his value is only a suggestion for the gateway, and it is
	// possible for the gateway to assign a different external port.
	SuggestedExternalPort int

	// RequestedLifetime specifies the duration of a port mapping with a NAT
	// gateway. The recommended value is 2 hours. To delete a mapping, leave
	// this field set to zero.
	RequestedLifetime time.Duration
}

// marshal marshals a MapRequest to its binary format.
func (mr *MapRequest) marshal() ([]byte, error) {
	switch mr.Protocol {
	case UDP, TCP:
	default:
		return nil, fmt.Errorf("natpmp: invalid MapRequest protocol: %s", mr.Protocol)
	}

	// InternalPort must be set, but SuggestedExternalPort is optional and may
	// be zero.
	if p := mr.InternalPort; p < 1 || p > math.MaxUint16 {
		return nil, fmt.Errorf("natpmp: InternalPort out of range: %d", p)
	}
	if p := mr.SuggestedExternalPort; p < 0 || p > math.MaxUint16 {
		return nil, fmt.Errorf("natpmp: SuggestedExternalPort out of range: %d", p)
	}

	// Version 0 is implicit when allocating the slice.
	b := make([]byte, 12)
	b[1] = uint8(mr.Protocol)
	binary.BigEndian.PutUint16(b[4:6], uint16(mr.InternalPort))
	binary.BigEndian.PutUint16(b[6:8], uint16(mr.SuggestedExternalPort))
	binary.BigEndian.PutUint32(b[8:12], uint32(mr.RequestedLifetime.Seconds()))

	return b, nil
}

// A MapResponse is the response from a NAT gateway when a port mapping has been
// established.
type MapResponse struct {
	// SinceStartOfEpoch specifies an estimated amount of time since the NAT
	// gateway has started, reset, or lost its mapping state.
	SinceStartOfEpoch time.Duration

	// InternalPort specifies the port of a service running on this host which
	// has received an external mapping from the NAT gateway.
	InternalPort int

	// ExternalPort specifies the external port chosen by the NAT gateway which
	// will forward traffic to the InternalPort for this host.
	ExternalPort int

	// Lifetime specifies the duration a port mapping will remain valid with
	// the NAT gateway.
	Lifetime time.Duration
}
