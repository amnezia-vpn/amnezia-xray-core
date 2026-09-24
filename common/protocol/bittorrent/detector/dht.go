package detector

import "github.com/xtls/xray-core/common"

const dhtMaxDepth = 8

type dhtMessage struct {
	y                byte
	hasTransactionID bool
	hasQueryName     bool
	hasArguments     bool
	hasResultWithID  bool
	hasErrorList     bool
}

func sniffDHT(payload []byte) error {
	if len(payload) == 0 {
		return common.ErrNoClue
	}
	if payload[0] != 'd' {
		return errNotBittorrent
	}
	var message dhtMessage
	if !message.parseDict(payload, 1) {
		return errNotBittorrent
	}
	switch message.y {
	case 'q':
		if !message.hasTransactionID || !message.hasQueryName || !message.hasArguments {
			return errNotBittorrent
		}
	case 'r':
		if !message.hasTransactionID || !message.hasResultWithID {
			return errNotBittorrent
		}
	case 'e':
		if !message.hasTransactionID || !message.hasErrorList {
			return errNotBittorrent
		}
	default:
		return errNotBittorrent
	}
	return nil
}

func (m *dhtMessage) parseDict(payload []byte, position int) bool {
	for position < len(payload) && payload[position] != 'e' {
		key, next, ok := parseString(payload, position)
		if !ok {
			return false
		}
		position = next
		if position >= len(payload) {
			return false
		}
		switch string(key) {
		case "y":
			value, next, ok := parseString(payload, position)
			if !ok || len(value) != 1 {
				return false
			}
			m.y = value[0]
			position = next
		case "t":
			value, next, ok := parseString(payload, position)
			if !ok || len(value) == 0 || len(value) > 16 {
				return false
			}
			m.hasTransactionID = true
			position = next
		case "q":
			value, next, ok := parseString(payload, position)
			if !ok || !isKnownDHTQuery(value) {
				return false
			}
			m.hasQueryName = true
			position = next
		case "a":
			if position >= len(payload) || payload[position] != 'd' {
				return false
			}
			next, ok := parseValue(payload, position, 1)
			if !ok {
				return false
			}
			m.hasArguments = true
			position = next
		case "r":
			if position >= len(payload) || payload[position] != 'd' || !m.parseResultDict(payload, position+1) {
				return false
			}
			next, ok := parseValue(payload, position, 1)
			if !ok {
				return false
			}
			m.hasResultWithID = true
			position = next
		case "e":
			if position >= len(payload) || payload[position] != 'l' || !m.parseErrorList(payload, position+1) {
				return false
			}
			next, ok := parseValue(payload, position, 1)
			if !ok {
				return false
			}
			m.hasErrorList = true
			position = next
		default:
			next, ok := parseValue(payload, position, 1)
			if !ok {
				return false
			}
			position = next
		}
	}
	return position < len(payload) && payload[position] == 'e'
}

func (m *dhtMessage) parseResultDict(payload []byte, position int) bool {
	foundID := false
	for position < len(payload) && payload[position] != 'e' {
		key, next, ok := parseString(payload, position)
		if !ok {
			return false
		}
		position = next
		if string(key) == "id" {
			value, next, ok := parseString(payload, position)
			if !ok || len(value) != 20 {
				return false
			}
			foundID = true
			position = next
			continue
		}
		next, ok = parseValue(payload, position, 1)
		if !ok {
			return false
		}
		position = next
	}
	return foundID
}

func (m *dhtMessage) parseErrorList(payload []byte, position int) bool {
	items := 0
	for position < len(payload) && payload[position] != 'e' {
		if items == 0 {
			next, ok := parseInt(payload, position)
			if !ok {
				return false
			}
			position = next
		} else if items == 1 {
			_, next, ok := parseString(payload, position)
			if !ok {
				return false
			}
			position = next
		} else {
			next, ok := parseValue(payload, position, 2)
			if !ok {
				return false
			}
			position = next
		}
		items++
	}
	return position < len(payload) && payload[position] == 'e' && items >= 2
}

func isKnownDHTQuery(name []byte) bool {
	switch string(name) {
	case "ping", "find_node", "get_peers", "announce_peer", "get", "put", "sample_infohashes":
		return true
	}
	return false
}

func parseValue(payload []byte, position, depth int) (int, bool) {
	if depth > dhtMaxDepth || position >= len(payload) {
		return 0, false
	}
	switch payload[position] {
	case 'i':
		return parseInt(payload, position)
	case 'l':
		position++
		for position < len(payload) && payload[position] != 'e' {
			next, ok := parseValue(payload, position, depth+1)
			if !ok {
				return 0, false
			}
			position = next
		}
		if position >= len(payload) {
			return 0, false
		}
		return position + 1, true
	case 'd':
		position++
		for position < len(payload) && payload[position] != 'e' {
			_, next, ok := parseString(payload, position)
			if !ok {
				return 0, false
			}
			next, ok = parseValue(payload, next, depth+1)
			if !ok {
				return 0, false
			}
			position = next
		}
		if position >= len(payload) {
			return 0, false
		}
		return position + 1, true
	default:
		_, next, ok := parseString(payload, position)
		if !ok {
			return 0, false
		}
		return next, true
	}
}

func parseInt(payload []byte, position int) (int, bool) {
	if position >= len(payload) || payload[position] != 'i' {
		return 0, false
	}
	position++
	if position < len(payload) && payload[position] == '-' {
		position++
	}
	start := position
	for position < len(payload) && payload[position] >= '0' && payload[position] <= '9' {
		position++
	}
	if position == start || position-start > 19 || position >= len(payload) || payload[position] != 'e' {
		return 0, false
	}
	return position + 1, true
}

func parseString(payload []byte, position int) (value []byte, next int, ok bool) {
	start := position
	for position < len(payload) && payload[position] >= '0' && payload[position] <= '9' {
		position++
	}
	if position == start || position-start > 4 || position >= len(payload) || payload[position] != ':' {
		return nil, 0, false
	}
	length := 0
	for _, character := range payload[start:position] {
		length = length*10 + int(character-'0')
	}
	position++
	if position+length > len(payload) {
		return nil, 0, false
	}
	return payload[position : position+length], position + length, true
}
