package detector

import "testing"

func TestSniffDHTRecognizesKRPC(t *testing.T) {
	arguments := "d2:id20:" + string(fixedNodeID[:]) + "e"
	result := "d2:id20:" + string(fixedNodeID[:]) + "e"
	cases := []struct {
		name    string
		payload []byte
	}{
		{"ping", dhtQuery("ping", arguments)},
		{"find node", dhtQuery("find_node", arguments)},
		{"get peers", dhtQuery("get_peers", arguments)},
		{"announce peer", dhtQuery("announce_peer", arguments)},
		{"bep 44 get", dhtQuery("get", arguments)},
		{"bep 44 put", dhtQuery("put", "d1:vd3:bari42ee2:id20:"+string(fixedNodeID[:])+"e")},
		{"sample infohashes", dhtQuery("sample_infohashes", arguments)},
		{"response", dhtResponse(result)},
		{"error", dhtDict("1:eli201e12:Server Errore", "1:t2:aa", "1:y1:e")},
		{"nested values", dhtResponse("d2:id20:" + string(fixedNodeID[:]) + "6:valuesl6:abcdefee")},
		{"trailing bytes", append(dhtQuery("ping", arguments), 'x', 'x')},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := sniffDHT(tc.payload); err != nil {
				t.Fatalf("sniffDHT() error = %v", err)
			}
		})
	}
}

func TestSniffDHTRejectsMalformedKRPC(t *testing.T) {
	arguments := "d2:id20:" + string(fixedNodeID[:]) + "e"
	deep := "d"
	for i := 0; i < 9; i++ {
		deep += "1:ad"
	}
	deep += "e1:q4:ping1:t2:aa1:y1:qe"
	cases := []struct {
		name    string
		payload []byte
	}{
		{"generic bencode", dhtDict("1:ai1ee")},
		{"missing y", dhtDict("1:t2:aa")},
		{"invalid y", dhtDict("1:t2:aa1:y1:x")},
		{"missing transaction", dhtDict("1:a"+arguments, "1:q4:ping", "1:y1:q")},
		{"empty transaction", dhtDict("1:a"+arguments, "1:q4:ping", "1:t0:", "1:y1:q")},
		{"long transaction", dhtDict("1:a"+arguments, "1:q4:ping", "1:t17:abcdefghijklmnopq", "1:y1:q")},
		{"unknown query", dhtQuery("unknown", arguments)},
		{"missing arguments", dhtDict("1:q4:ping", "1:t2:aa", "1:y1:q")},
		{"response without result", dhtDict("1:t2:aa", "1:y1:r")},
		{"response without id", dhtResponse("d1:xi1ee")},
		{"malformed error", dhtDict("1:eli201ee", "1:t2:aa", "1:y1:e")},
		{"excessive nesting", []byte(deep)},
		{"overlong integer", []byte("d1:eli12345678901234567890e1:xe1:t2:aa1:y1:ee")},
		{"truncated string", []byte("d1:t20:short1:y1:qe")},
		{"malformed dictionary", []byte("d1:t2:aa1:y1:q")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := sniffDHT(tc.payload); err == nil {
				t.Fatal("sniffDHT() matched malformed datagram")
			}
		})
	}
}
