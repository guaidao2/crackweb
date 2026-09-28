package oob

import (
	"encoding/binary"
	"strings"
)

// This file implements just enough of the DNS wire format to answer queries:
// parse the question, echo it back, and claim no answers. crackweb is not
// resolving anything — it is recording that a lookup happened and who asked.

// dnsHeaderLen is the fixed header size.
const dnsHeaderLen = 12

// dns flags for the reply: QR (response), RD (recursion desired, echoed) and
// RA (recursion available), with RCODE 0.
const dnsReplyFlags = 0x8180

// maxDNSNameLen bounds a name to the protocol limit, so a malformed packet
// cannot make the parser run away.
const maxDNSNameLen = 255

// parseDNSQuestion extracts the queried name and returns the offset just past
// the question section.
func parseDNSQuestion(packet []byte) (name string, end int, ok bool) {
	if len(packet) < dnsHeaderLen {
		return "", 0, false
	}
	qdCount := binary.BigEndian.Uint16(packet[4:6])
	if qdCount == 0 {
		return "", 0, false
	}

	var builder strings.Builder
	offset := dnsHeaderLen
	for {
		if offset >= len(packet) {
			return "", 0, false
		}
		length := int(packet[offset])
		offset++

		switch {
		case length == 0:
			// End of the name. The question continues with QTYPE and QCLASS.
			if offset+4 > len(packet) {
				return "", 0, false
			}
			return builder.String(), offset + 4, true

		case length&0xc0 != 0:
			// A compression pointer. Nothing we send needs to follow it, and
			// following it is where parsers get exploited, so stop here.
			return builder.String(), offset + 1, true

		default:
			if offset+length > len(packet) || builder.Len()+length > maxDNSNameLen {
				return "", 0, false
			}
			if builder.Len() > 0 {
				builder.WriteByte('.')
			}
			builder.Write(packet[offset : offset+length])
			offset += length
		}
	}
}

// buildDNSReply produces a response that repeats the question and carries no
// answers.
func buildDNSReply(query []byte, questionEnd int) []byte {
	if questionEnd > len(query) || questionEnd < dnsHeaderLen {
		return nil
	}
	reply := make([]byte, questionEnd)
	copy(reply, query[:questionEnd])

	// Turn the header into a response: keep the transaction ID and the
	// question, set QR/RD/RA and clear the section counts.
	binary.BigEndian.PutUint16(reply[2:4], dnsReplyFlags)
	binary.BigEndian.PutUint16(reply[4:6], 1) // QDCOUNT
	binary.BigEndian.PutUint16(reply[6:8], 0) // ANCOUNT
	binary.BigEndian.PutUint16(reply[8:10], 0)
	binary.BigEndian.PutUint16(reply[10:12], 0)
	return reply
}
