package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
)

func main() {
	l, err := net.Listen("tcp", ":1080")
	if err != nil {
		panic(err)
	}
	for {
		conn, err := l.Accept()
		if err != nil {
			// too many open file
			log.Println("accept conn error %v", err)
			continue
		}

		go handle(conn)
	}
}

func handle(conn net.Conn) {
	defer conn.Close()

	var tmp [5]byte
	rd := bufio.NewReader(conn)
	if _, err := rd.Read(tmp[:1]); err != nil {
		log.Println("Read conn version error", err)
		return
	}
	if tmp[0] != 0x05 {
		log.Println("version not match", tmp[0])
		return
	}

	if _, err := rd.Read(tmp[:1]); err != nil {
		log.Println("Read conn nmethods error", err)
		return
	}
	nmethods := int(tmp[0])
	if nmethods > 5 {
		log.Println("too many conn methods error")
		return
	}
	if n, err := rd.Read(tmp[:nmethods]); err != nil || n != nmethods {
		log.Println("Read conn methods error", err)
		return
	}

	noauth := false
	for _, m := range tmp[:nmethods] {
		if m == 0 {
			noauth = true
			break
		}
	}
	if !noauth {
		log.Println("only support no auth")
		conn.Write([]byte{0x05, 0xff})
		return
	}
	conn.Write([]byte{0x05, 0x00})

	// read request
	if _, err := rd.Read(tmp[:1]); err != nil {
		log.Println("Read conn version error", err)
		return
	}
	if tmp[0] != 0x05 {
		log.Println("version not match", tmp[0])
	}

	if _, err := rd.Read(tmp[:1]); err != nil {
		log.Println("Read conn version error", err)
		return
	}
	cmd := tmp[0]
	switch cmd {
	case 0x01:
	case 0x02:
	case 0x03:
	default:
		log.Println("unknown command")
		return
	}
	if cmd != 0x01 {
		log.Println("olny support connect command", cmd)
		return
	}

	// ignore RSV
	if _, err := rd.Read(tmp[:1]); err != nil {
		log.Println("Read conn version error", err)
		return
	}

	if _, err := rd.Read(tmp[:1]); err != nil {
		log.Println("Read conn atype error", err)
		return
	}
	atype := tmp[0]
	switch atype {
	case 0x01:
	case 0x03:
	case 0x04:
	default:
		log.Println("unknown atype")
		return
	}
	var scon net.Conn
	if atype == 0x01 {
		if _, err := rd.Read(tmp[:4]); err != nil {
			log.Println("Read conn dst.addr error", err)
			return
		}
		dstIp := net.IPv4(tmp[0], tmp[1], tmp[2], tmp[3])
		if _, err := rd.Read(tmp[:2]); err != nil {
			log.Println("Read conn dst.port error", err)
			return
		}
		dstPort := (int(tmp[0]) << 8) + int(tmp[1])

		addr := &net.TCPAddr{IP: dstIp, Port: dstPort}
		log.Printf("connect to %v\n", addr)
		var err error
		scon, err = net.DialTCP("tcp", nil, addr)
		if err != nil {
			log.Println("connect remote error", err)
			return
		}
	} else if atype == 0x03 {
		if _, err := rd.Read(tmp[:1]); err != nil {
			log.Println("Read conn domain length error", err)
			return
		}
		l := tmp[0]
		domain := make([]byte, l)
		if n, err := rd.Read(domain); err != nil || n != int(l) {
			log.Println("Read conn domain error", err)
			return
		}
		if _, err := rd.Read(tmp[:2]); err != nil {
			log.Println("Read conn dst.port error", err)
			return
		}
		dstPort := (int(tmp[0]) << 8) + int(tmp[1])
		log.Printf("connect to %s:%d\n", domain, dstPort)
		var err error
		scon, err = net.Dial("tcp", fmt.Sprintf("%s:%d", domain, dstPort))
		if err != nil {
			log.Println("connect remote error", err)
			return
		}

	} else {
		log.Println("unsupport ipv6 ")
		return
	}

	ld := scon.LocalAddr().(*net.TCPAddr)
	conn.Write([]byte{0x05, 0x00, 0x00, 0x01, ld.IP[0], ld.IP[1], ld.IP[2], ld.IP[3], byte(ld.Port >> 8), byte(ld.Port & 0xff)})

	go io.Copy(scon, rd)
	io.Copy(conn, scon)
	scon.Close()
}
