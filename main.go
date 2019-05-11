package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
)

var help = `tlsdb - An interactive TLS protocol debugger!
Commands
- b <contentType> break on specific record or break again to delete breakpoints. e.g. 23 for Application Data
- a <ip> <port> add a route. e.g. a 127.0.0.1 1589
- r <ip> <port> remove a route. e.g. r 127.0.0.1 1589
- l list all routes
- s <ip> <port> set a default route. e.g. s 127.0.0.1 1589
- f forward the record the default route.
- d drop the current record. Note: You must drop or forward the record.
- c continue and forward the record if any.
- q quit the program
`
var logger *log.Logger
var routeTable map[EndPoint]*RouteEntry
var breakpoints map[tlsRecordType]bool
var defaultroute *EndPoint
var inputcg chan []byte

type commandtype int

const (
	breakType commandtype = iota
	addRoute
	removeRoute
	listRoute
	setDefaultRoute
	forwardRecord
	dropRecord
	quitProgram
	continueType
	unknown
)

type tlsRecordType byte

const (
	ChangeCipher tlsRecordType = 0x14 + iota
	Alert
	Handshake
	Application
	Heartbear
)

type command struct {
	cmd  commandtype
	args []string
}

type tlsRecord struct {
	Remote  net.Addr
	Type    tlsRecordType
	Version []byte
	Length  uint16
	Data    []byte
}

func (r *tlsRecord) toBytes() []byte {
	buffer := bytes.Buffer{}
	tpbuffer := make([]byte, 2)
	binary.BigEndian.PutUint16(tpbuffer, r.Length)
	buffer.Write([]byte{byte(r.Type)})
	buffer.Write(r.Version)
	buffer.Write(tpbuffer)
	buffer.Write(r.Data)
	return buffer.Bytes()
}

func getCommandType(c byte) commandtype {
	switch c {
	case 'b':
		return breakType
	case 'a':
		return addRoute
	case 'l':
		return listRoute
	case 's':
		return setDefaultRoute
	case 'f':
		return forwardRecord
	case 'd':
		return dropRecord
	case 'q':
		return quitProgram
	case 'c':
		return continueType
	default:
		return unknown
	}
}

func getNextCommand(scanner *bufio.Scanner) *command {
	scanner.Scan()
	line := scanner.Text()
	line = strings.TrimSpace(line)
	tks := strings.Split(line, " ")
	for idx, tk := range tks {
		tks[idx] = strings.TrimSpace(tk)
	}
	if len(tks) == 0 || len(tks[0]) != 1 || getCommandType(tks[0][0]) == unknown {
		return nil
	}
	return &command{
		cmd:  getCommandType(tks[0][0]),
		args: tks[1:]}
}

func readTLSRecord(conn io.ReadWriter) (*tlsRecord, error) {
	buf := make([]byte, 5)
	if _, err := conn.Read(buf); err != nil {
		return nil, err
	}
	recordType := buf[0]
	//fmt.Println(buf)
	if recordType < 0x14 || recordType > 0x18 {
		return nil, errors.New(fmt.Sprintf("Unknwon record type %v...\nWe will close the connection\n", buf[0]))
	}
	version := buf[1:3]
	recordLength := binary.BigEndian.Uint16(buf[3:5])
	if recordLength > 1000 {
		logger.Printf("Long record found: %v\n", recordLength)
	}
	buf = make([]byte, recordLength)
	l := 0
	for l < int(recordLength) {
		r := 0
		if (int)(l+512) < int(recordLength) {
			r = l + 512
		} else {
			r = int(recordLength)
		}
		//fmt.Printf("%v:[%v -> %v]\n", recordLength, l, r)
		if nread, err := conn.Read(buf[l:r]); err != nil {
			return nil, err
		} else if nread != r-l {
			l = l + nread
			continue
		}
		l = r
	}
	r := &tlsRecord{
		Type:    tlsRecordType(recordType),
		Version: version,
		Length:  recordLength,
		Data:    buf}
	//fmt.Printf("%v\n", *r)
	return r, nil
}

func initialize(address *string) (chan *tlsRecord, chan []byte, error) {
	ln, err := net.Listen("tcp", *address)
	if err != nil {
		return nil, nil, err
	}
	c := make(chan *tlsRecord, 1024)
	inc := make(chan []byte, 1024)
	go func() {
		max_retry := 5
		current := 0
		for current < max_retry {
			conn, err := ln.Accept()
			if err != nil {
				current = current + 1
				continue
			}
			current = 0
			go func() {
				for {
					recvdata := <-inc
					//logger.Println("Writing back")
					conn.Write(recvdata)
				}
			}()
			for {
				record, err := readTLSRecord(conn)
				if err != nil {
					logger.Println(err.Error())
					break
				}
				record.Remote = conn.RemoteAddr()
				c <- record
			}
			conn.Close()
		}
	}()
	go func() {
		for {
			if defaultroute != nil && routeTable != nil {
				re := routeTable[*defaultroute]
				record, err := readTLSRecord(re)
				if err != nil {
					logger.Println(err.Error())
					break
				}
				if record != nil {
					inputcg <- record.toBytes()
				}
			}
		}
	}()
	return c, inc, nil
}

func handleCMD(cmd *command, record *tlsRecord) (bool, error) {
	var parseEP = func(sip string, sport string) (*EndPoint, error) {
		ips, err := net.LookupIP(sip)
		if err != nil {
			return nil, err
		}
		if len(ips) == 0 {
			return nil, errors.New("IP not found.")
		}
		ip := ips[0]
		port, err := strconv.Atoi(sport)
		if err != nil {
			return nil, err
		}
		ep := NewEndPoint(ip, uint16(port))
		return ep, nil
	}
	bk := false
	switch cmd.cmd {
	case breakType:
		if len(cmd.args) != 1 {
			return false, errors.New("Args wrong.")
		}
		result, err := strconv.Atoi(cmd.args[0])
		if err != nil {
			return false, errors.New("Args wrong.")
		}
		bp := byte(result)
		rt := tlsRecordType(bp)
		if _, ok := breakpoints[rt]; ok {
			delete(breakpoints, rt)
		} else {
			breakpoints[tlsRecordType(bp)] = true
		}
	case addRoute:
		if len(cmd.args) != 2 {
			return false, errors.New("Args wrong.")
		}
		ep, err := parseEP(cmd.args[0], cmd.args[1])
		if err != nil {
			return false, err
		}
		re := NewRoutingEntry(ep)
		re.Run()
		if len(routeTable) == 0 {
			defaultroute = ep
		}
		routeTable[*ep] = re
		fmt.Println("Route added")
	case removeRoute:
		if len(cmd.args) != 2 {
			return false, errors.New("Args wrong.")
		}
		ep, err := parseEP(cmd.args[0], cmd.args[1])
		if err != nil {
			return false, err
		}
		if _, ok := routeTable[*ep]; !ok {
			return false, errors.New("No such route.")
		}
		re := routeTable[*ep]
		re.Close()
		delete(routeTable, *ep)
	case listRoute:
		for ep := range routeTable {
			fmt.Printf("%v %v", ep.ToIP().String(), ep.Port)
			if ep == *defaultroute {
				fmt.Printf(" <== default")
			}
			fmt.Printf("\n")
		}
	case setDefaultRoute:
		if len(cmd.args) != 2 {
			return false, errors.New("Args wrong.")
		}
		newep, err := parseEP(cmd.args[0], cmd.args[1])
		if err != nil {
			return false, err
		}
		if _, ok := routeTable[*newep]; !ok {
			return false, errors.New("No such route.")
		}
		defaultroute = newep
	case continueType:
		if record == nil {
			return true, nil
		}
		fallthrough
	case forwardRecord:
		re := routeTable[*defaultroute]
		if record == nil {
			return false, errors.New("No record")
		}
		re.Write(record.toBytes())
		bk = true
	case dropRecord:
		bk = true
	case unknown:
		return false, errors.New("Unknown command")
	}
	return bk, nil
}

func main() {
	logger = log.New(os.Stdout, "", log.Ldate|log.Ltime|log.Lshortfile)
	address := flag.String("addr", "0.0.0.0:1589", "The listening address.")
	flag.Parse()
	fmt.Printf("Starting tlsdb on %s...", *address)
	tlsc, inputc, err := initialize(address)
	inputcg = inputc
	if err != nil {
		panic(err)
	}
	fmt.Println(help)
	c := make(chan os.Signal)
	scanner := bufio.NewScanner(os.Stdin)
	breakpoints = map[tlsRecordType]bool{0x17: true}
	routeTable = map[EndPoint]*RouteEntry{}
	for {
		bk := false
		var currentRecord *tlsRecord = nil
		signal.Notify(c, syscall.SIGINT)
		select {
		case r := <-tlsc:
			currentRecord = r
			if _, ok := breakpoints[r.Type]; !ok {
				bk = false
				if defaultroute != nil {
					if re, okk := routeTable[*defaultroute]; okk {
						re.Write(r.toBytes())
					}
				}
				break
			}
			fmt.Printf("Receive a new block from %v, Type: %v, Length: %v\n", r.Remote, r.Type, r.Length)
			bk = true
		case <-c:
			signal.Reset()
			fmt.Println("Receive SIGINT.")
			bk = true
		}
		if bk {
			var cmd *command
			for {
				fmt.Print(">")
				if cmd = getNextCommand(scanner); cmd == nil {
					fmt.Println("Wrong syntax!")
				} else {
					bk, err := handleCMD(cmd, currentRecord)
					if err != nil {
						fmt.Println(err.Error())
					}
					if bk {
						break
					}
				}
			}
		}
	}
}
