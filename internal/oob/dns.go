package oob

import (
	"encoding/binary"
	"net"
	"strings"
)

// This file implements just enough of the DNS wire format to answer queries:
// parse the question, echo it back, and — for the names a DNS-rebinding probe
// mints — claim a single A record whose address changes between lookups.
// Everything else about crackweb's DNS listener is the same as it always was:
// it is recording that a lookup happened and who asked.

// dnsHeaderLen is the fixed header size.
const dnsHeaderLen = 12

// dns flags for the reply: QR (response), RD (recursion desired, echoed) and
// RA (recursion available), with RCODE 0.
const dnsReplyFlags = 0x8180

// dnsTypeA is the A record type, the only one crackweb answers with.
const dnsTypeA = 1

// dnsClassIN is the internet class.
const dnsClassIN = 1

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

// questionType returns the QTYPE of a question whose end offset the parser
// reported. A rebinding answer is only meaningful for an A query — an AAAA
// query would be answered with the wrong record type and the resolver would
// discard it — so the caller uses this to decide whether to answer at all.
func questionType(packet []byte, questionEnd int) uint16 {
	if questionEnd < dnsHeaderLen+4 || questionEnd > len(packet) {
		return 0
	}
	// The question section ends with QTYPE then QCLASS, each two bytes.
	return binary.BigEndian.Uint16(packet[questionEnd-4 : questionEnd-2])
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

// buildDNSReplyA produces a response that repeats the question and carries one
// A answer with the given address.
//
// This is the one place crackweb resolves a name rather than only recording the
// lookup: a DNS-rebinding probe needs the answer to change between two lookups,
// which cannot be expressed by a server that answers nothing. The TTL is under
// the caller's control so it can be set to zero — no cache, so the second lookup
// actually reaches this server instead of being served from a resolver's memory.
func buildDNSReplyA(query []byte, questionEnd int, ip net.IP, ttl uint32) []byte {
	quad := ip.To4()
	if quad == nil {
		return nil
	}
	reply := buildDNSReply(query, questionEnd)
	if reply == nil {
		return nil
	}
	binary.BigEndian.PutUint16(reply[6:8], 1) // ANCOUNT: one answer follows

	// NAME is a compression pointer to the question's name, which begins at
	// offset 12 in every query this builds a reply for. The rest is a standard
	// A record: TYPE, CLASS, TTL, RDLENGTH, then the four address bytes.
	answer := make([]byte, 16)
	answer[0], answer[1] = 0xc0, 0x0c
	binary.BigEndian.PutUint16(answer[2:4], dnsTypeA)
	binary.BigEndian.PutUint16(answer[4:6], dnsClassIN)
	binary.BigEndian.PutUint32(answer[6:10], ttl)
	binary.BigEndian.PutUint16(answer[10:12], 4)
	copy(answer[12:16], quad)
	return append(reply, answer...)
}
