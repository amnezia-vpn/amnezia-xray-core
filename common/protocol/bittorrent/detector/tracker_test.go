package detector

import "testing"

func TestSniffUDPTrackerRecognizesRequests(t *testing.T) {
	cases := []struct {
		name    string
		payload []byte
	}{
		{"connect", udpTrackerConnect(0xdeadbeef)},
		{"announce events", udpTrackerAnnounce(0, 6881)},
		{"announce completed", udpTrackerAnnounce(1, 6881)},
		{"announce started", udpTrackerAnnounce(2, 6881)},
		{"announce stopped", udpTrackerAnnounce(3, 6881)},
		{"scrape one hash", udpTrackerScrape(fixedInfoHash)},
		{"scrape two hashes", udpTrackerScrape(fixedInfoHash, fixedNodeID)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := sniffUDPTracker(tc.payload); err != nil {
				t.Fatalf("sniffUDPTracker() error = %v", err)
			}
		})
	}
}

func TestSniffUDPTrackerRejectsInvalidRequests(t *testing.T) {
	wrongMagic := udpTrackerConnect(1)
	wrongMagic[0] ^= 1
	wrongAction := udpTrackerConnect(1)
	wrongAction[11] = 1
	wrongLength := udpTrackerAnnounce(0, 6881)[:97]
	emptyScrape := udpTrackerScrape()
	misalignedScrape := append(udpTrackerScrape(fixedInfoHash), 0)
	cases := []struct {
		name    string
		payload []byte
	}{
		{"wrong magic", wrongMagic},
		{"wrong connect action", wrongAction},
		{"wrong announce length", wrongLength},
		{"wrong announce action", func() []byte { b := udpTrackerAnnounce(0, 6881); b[11] = 2; return b }()},
		{"invalid event", udpTrackerAnnounce(4, 6881)},
		{"zero port", udpTrackerAnnounce(0, 0)},
		{"scrape without hash", emptyScrape},
		{"scrape misaligned", misalignedScrape},
		{"random", seededBytes(9, 96)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := sniffUDPTracker(tc.payload); err == nil {
				t.Fatal("sniffUDPTracker() matched invalid datagram")
			}
		})
	}
}
