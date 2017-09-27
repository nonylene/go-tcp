package main

import (
	"encoding/binary"
	"fmt"
	"net"
)

type CurrentSEQ struct {
	//  segment sequence number
	SegSeq int32
	//  Segment acknowledgment number
	SegAck int32
	//  Segment length
	SegLen int32
	//  Segment window
	SegWnd int16
	//  Segment urgent pointer
	SegUp int16
	// Segment precedence value
	SegPrc int32
}

type Status int

const (
	CLOSED Status = iota
	LISTEN
	SYN_RCVD
	SYN_SENT
	ESTAB
	FINWAIT_1
	FINWAIT_2
	CLOSE_WAIT
	LAST_ACK
	CLOSING
	TIME_WAIT
)

type TCB struct {
	Status Status

	//  Send Sequence Variables
	//  send unacknowledged
	SndUna uint32
	// send next
	SndNxt uint32
	// send window
	SndWnd uint16
	// send urgent pouinter
	SndUp uint16
	// segment sequence number used for last window update
	SndWl1 uint32
	// segment acknowledgment number used for last window update
	SndWl2 uint32
	// initial send sequence number
	Iss uint32

	// Receive Seuence Variables
	//  receive next
	RcvNxt uint32
	//  receive window
	RcvWnd uint16
	// receive urgent pouinter
	RcvUp uint16
	// initial receive sequence number
	Irs uint32
}

type TCPInfo struct {
	srcAddr *net.IPAddr
	dstAddr *net.IPAddr
	header  TCPHeader
}

type TCPHeader struct {
	SrcPort       uint16
	DstPort       uint16
	SeqNum        uint32
	AckNum        uint32
	DataOffSet    uint16 // 8 byte
	URG           bool
	ACK           bool
	PSH           bool
	RST           bool
	SYN           bool
	FIN           bool
	Window        uint16
	CheckSum      uint16
	UrgentPointer uint16
	// Options mendokusai node ignore
}

// func parseTCPHeader(bytes []byte) (TCPHead, error) {
func parseTCPHeader(bytes []byte) TCPHeader {
	head := TCPHeader{}
	head.SrcPort = binary.BigEndian.Uint16(bytes[0:2])
	head.DstPort = binary.BigEndian.Uint16(bytes[2:4])
	head.SeqNum = binary.BigEndian.Uint32(bytes[4:8])
	head.AckNum = binary.BigEndian.Uint32(bytes[8:12])
	head.DataOffSet = uint16(bytes[12]) >> 4
	flag := binary.BigEndian.Uint16(bytes[12:14])
	head.URG = flag&0x20 != 0
	head.ACK = flag&0x10 != 0
	head.PSH = flag&0x08 != 0
	head.RST = flag&0x04 != 0
	head.SYN = flag&0x02 != 0
	head.FIN = flag&0x01 != 0
	head.Window = binary.BigEndian.Uint16(bytes[14:16])
	head.CheckSum = binary.BigEndian.Uint16(bytes[16:18])
	head.UrgentPointer = binary.BigEndian.Uint16(bytes[18:20])
	// option -> ignore
	return head
}

func readTCP(tcb *TCB, c *net.IPConn) (*TCPInfo, []byte) {
	lcl := c.LocalAddr()
	dst, _ := net.ResolveIPAddr(lcl.Network(), lcl.String())

	// header
	// 2000 byte
	data := make([]byte, 2000)
	n, src, _ := c.ReadFromIP(data)
	data = data[:n]
	fmt.Println(data)

	head := parseTCPHeader(data)

	info := TCPInfo{
		header:  head,
		srcAddr: src,
		dstAddr: dst,
	}

	fmt.Printf("%+v\n", info)

	payload := data[int(head.DataOffSet)*4:]
	fmt.Println(payload)

	return &info, payload
}

func setAll(orig []byte, data []byte, index int) {
	for i := 0; i < len(data); i++ {
		orig[index+i] = data[i]
	}
}

func createCheckSum(info *TCPInfo, header []byte, length uint16) uint16 {
	data := make([]byte, 12+length)
	setAll(data, info.srcAddr.IP.To4(), 0)
	setAll(data, info.dstAddr.IP.To4(), 4)

	binary.BigEndian.PutUint16(data[8:10], 6)
	binary.BigEndian.PutUint16(data[10:12], length)

	setAll(data, header, 12)

	sum := uint16(0)
	for i := 0; i < len(data)/2; i++ {
		x := binary.BigEndian.Uint16(data[i*2 : i*2+2])
		sum += ^x
	}
	return ^sum
}

func sendTCP(tcb *TCB, c *net.IPConn, info *TCPInfo, payload []byte) {
	// XXX
	optLen := 0
	headLen := 20 + optLen
	length := headLen + len(payload)

	head := info.header
	data := make([]byte, headLen)

	binary.BigEndian.PutUint16(data[0:2], head.SrcPort)
	binary.BigEndian.PutUint16(data[2:4], head.DstPort)
	binary.BigEndian.PutUint32(data[4:8], head.SeqNum)
	binary.BigEndian.PutUint32(data[8:12], head.AckNum)

	dataOffFlags := uint16(headLen/4) >> 12
	if head.URG {
		dataOffFlags |= 0x20
	}
	if head.ACK {
		dataOffFlags |= 0x10
	}
	if head.PSH {
		dataOffFlags |= 0x08
	}
	if head.RST {
		dataOffFlags |= 0x04
	}
	if head.SYN {
		dataOffFlags |= 0x02
	}
	if head.FIN {
		dataOffFlags |= 0x01
	}

	binary.BigEndian.PutUint16(data[12:14], dataOffFlags)

	binary.BigEndian.PutUint16(data[14:16], head.Window)
	binary.BigEndian.PutUint16(data[16:18], createCheckSum(info, data, uint16(length)))
	binary.BigEndian.PutUint16(data[18:20], 0)

	s := append(data, payload...)
	fmt.Println(s)

	c.Write(s)
}

func handleTCP(tcb *TCB, c *net.IPConn) {
	info, payload := readTCP(tcb, c)

	// if tcb != nil {
	// }
	tcb = &TCB{
		Status: CLOSED,
		Iss:    0,
	}

	switch tcb.Status {
	case CLOSED:
		info = handleTCPClose(tcb, info, payload)
		sendTCP(tcb, c, info, make([]byte, 0))
	default:
		// nop
	}
}

func handleTCPClose(tcb *TCB, info *TCPInfo, payload []byte) *TCPInfo {
	header := info.header
	return &TCPInfo{
		srcAddr: info.dstAddr,
		dstAddr: info.srcAddr,
		header: TCPHeader{
			SrcPort: header.DstPort,
			DstPort: header.SrcPort,
			SeqNum:  0,
			AckNum:  header.SeqNum,
			ACK:     true,
			SYN:     true,
			Window:  100,
		},
	}
}

func main() {
	addr, err := net.ResolveIPAddr("ip", "127.0.0.1")
	if err != nil {
		fmt.Println(err)
		return
	}
	conn, err := net.ListenIP("ip:tcp", addr)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer conn.Close()
	var tcb *TCB
	for {
		handleTCP(tcb, conn)
	}
}
