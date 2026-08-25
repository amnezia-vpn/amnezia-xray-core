package detector

import (
	"encoding/binary"
	"math/rand"
	"strconv"
	"strings"
)

type utpExtension struct {
	id   byte
	data []byte
}

var (
	fixedNodeID   = [20]byte{0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23}
	fixedInfoHash = [20]byte{0xdd, 0x82, 0x55, 0xec, 0xdc, 0x7c, 0xa5, 0x5f, 0xb0, 0xbb, 0xf8, 0x13, 0x23, 0xd8, 0x70, 0x62, 0xdb, 0x1f, 0x6d, 0x1c}
)

func seededBytes(seed int64, n int) []byte {
	r := rand.New(rand.NewSource(seed))
	b := make([]byte, n)
	if _, err := r.Read(b); err != nil {
		panic(err)
	}
	return b
}

func peerHandshake(peerID string) []byte {
	b := make([]byte, 68)
	b[0] = 19
	copy(b[1:20], "BitTorrent protocol")
	copy(b[20:28], []byte{0, 0, 0, 0, 0, 0x10, 0, 0x05})
	copy(b[28:48], fixedInfoHash[:])
	copy(b[48:68], peerID)
	return b
}

func utpPacket(typ byte, connectionID uint16, timestamp uint32, extensions []utpExtension, payload []byte) []byte {
	b := make([]byte, 20, 20+len(payload)+16)
	b[0] = typ<<4 | 1
	if len(extensions) > 0 {
		b[1] = extensions[0].id
	}
	binary.BigEndian.PutUint16(b[2:4], connectionID)
	binary.BigEndian.PutUint32(b[4:8], timestamp)
	binary.BigEndian.PutUint32(b[8:12], 900)
	binary.BigEndian.PutUint32(b[12:16], 0x100000)
	binary.BigEndian.PutUint16(b[16:18], 101)
	binary.BigEndian.PutUint16(b[18:20], 100)
	for i, extension := range extensions {
		next := byte(0)
		if i+1 < len(extensions) {
			next = extensions[i+1].id
		}
		b = append(b, next, byte(len(extension.data)))
		b = append(b, extension.data...)
	}
	return append(b, payload...)
}

func dnsQueryFor(name string, transactionID, flags uint16) []byte {
	b := make([]byte, 12, 12+len(name)+6)
	binary.BigEndian.PutUint16(b[0:2], transactionID)
	binary.BigEndian.PutUint16(b[2:4], flags)
	binary.BigEndian.PutUint16(b[4:6], 1)
	for _, label := range strings.Split(name, ".") {
		b = append(b, byte(len(label)))
		b = append(b, label...)
	}
	b = append(b, 0, 0, 1, 0, 1)
	return b
}

func ednsTwoExtraQuery(name string, transactionID uint16) []byte {
	b := dnsQueryFor(name, transactionID, 0x0100)
	binary.BigEndian.PutUint16(b[10:12], 2)
	return append(b,
		0, 0, 0x29, 0x10, 0, 0, 0x80, 0, 0, 0,
		0, 0, 0x29, 0x10, 0, 0, 0x80, 0, 0, 0,
	)
}

func twoQuestionQuery(firstName, secondName string, transactionID uint16) []byte {
	b := dnsQueryFor(firstName, transactionID, 0x0100)
	binary.BigEndian.PutUint16(b[4:6], 2)
	for _, label := range strings.Split(secondName, ".") {
		b = append(b, byte(len(label)))
		b = append(b, label...)
	}
	return append(b, 0, 0, 1, 0, 1)
}

func answerCarryingQuery(name string, transactionID uint16) []byte {
	b := dnsQueryFor(name, transactionID, 0x0100)
	binary.BigEndian.PutUint16(b[6:8], 1)
	return append(b,
		0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 0, 0, 4, 127, 0, 0, 1,
	)
}

func dnsTrackerAnnounceCollision(transactionID uint16) []byte {
	b := dnsQueryFor("proxy.example.test", transactionID, 0x0100)
	binary.BigEndian.PutUint16(b[10:12], 1)
	b = append(b,
		0, 0, 0x29, 0x10, 0, 0, 0x80, 0, 0, 0, 0x33,
		0, 2, 0, 0x2f,
	)
	b = append(b, make([]byte, 45)...)
	return append(b, 0x12, 0x34)
}

func dnsTrackerScrapeCollision(transactionID uint16) []byte {
	b := dnsQueryFor("aaaaaaaa.example", transactionID, 0x0100)
	binary.BigEndian.PutUint16(b[10:12], 2)
	return append(b,
		0, 0, 0x29, 0x10, 0, 0, 0x80, 0, 0, 0, 0,
		0, 0, 0x29, 0x10, 0, 0, 0x80, 0, 0, 0, 0,
	)
}

func dhtDict(parts ...string) []byte {
	return []byte("d" + strings.Join(parts, "") + "e")
}

func dhtQuery(name string, arguments string) []byte {
	return dhtDict("1:a"+arguments, "1:q"+strconv.Itoa(len(name))+":"+name, "1:t2:aa", "1:y1:q")
}

func dhtResponse(result string) []byte {
	return dhtDict("1:r"+result, "1:t2:aa", "1:y1:r")
}

func udpTrackerConnect(transactionID uint32) []byte {
	b := make([]byte, 16)
	binary.BigEndian.PutUint64(b[:8], 0x41727101980)
	binary.BigEndian.PutUint32(b[8:12], 0)
	binary.BigEndian.PutUint32(b[12:16], transactionID)
	return b
}

func udpTrackerAnnounce(event uint32, port uint16) []byte {
	b := make([]byte, 98)
	binary.BigEndian.PutUint64(b[:8], 0x1234567890abcdef)
	binary.BigEndian.PutUint32(b[8:12], 1)
	binary.BigEndian.PutUint32(b[12:16], 7)
	copy(b[16:36], fixedInfoHash[:])
	binary.BigEndian.PutUint32(b[80:84], event)
	binary.BigEndian.PutUint16(b[96:98], port)
	return b
}

func udpTrackerScrape(hashes ...[20]byte) []byte {
	b := make([]byte, 16+20*len(hashes))
	binary.BigEndian.PutUint64(b[:8], 0x1234567890abcdef)
	binary.BigEndian.PutUint32(b[8:12], 2)
	binary.BigEndian.PutUint32(b[12:16], 8)
	for i, hash := range hashes {
		copy(b[16+i*20:], hash[:])
	}
	return b
}
