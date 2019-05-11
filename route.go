package main

import (
	"fmt"
	"net"
)

type EndPoint struct {
	IP   [4]byte
	Port uint16
}

type RouteEntry struct {
	conn        net.Conn
	ep          EndPoint
	restartchan chan bool
	readychan   chan bool
	closechan   chan bool
}

func NewEndPoint(ip net.IP, port uint16) *EndPoint {
	ipbs := ip.To4()
	ep := EndPoint{}
	for i := 0; i < 4; i++ {
		ep.IP[i] = ipbs[i]
	}
	ep.Port = port
	return &ep
}

func (ep *EndPoint) ToIP() net.IP {
	return net.IPv4(ep.IP[0], ep.IP[1], ep.IP[2], ep.IP[3])
}

func NewRoutingEntry(ep *EndPoint) *RouteEntry {
	return &RouteEntry{
		ep:          *ep,
		restartchan: make(chan bool),
		readychan:   make(chan bool),
		closechan:   make(chan bool, 1024)}
}

func (re *RouteEntry) run() {
	max_retry := 5
	retries := 0
	for retries <= max_retry {
		var err error
		if re.conn, err = net.Dial("tcp", fmt.Sprintf("%s:%s", re.ep.ToIP().String(), fmt.Sprintf("%v", re.ep.Port))); err != nil {
			retries = retries + 1
			continue
		}
		re.readychan <- true
		<-re.restartchan
		toclose := false
		select {
		case <-re.closechan:
			toclose = true
		default:
			toclose = false
		}
		re.conn.Close()
		if toclose {
			break
		}
	}
}

func (re *RouteEntry) Run() {
	go re.run()
	<-re.readychan
}

func (re *RouteEntry) restart() {
	re.restartchan <- true
	<-re.readychan
}

func (re *RouteEntry) Read(buf []byte) (int, error) {
	var nread int
	var err error
	for {
		if nread, err = re.conn.Read(buf); err != nil {
			re.restart()
			continue
		}
		break
	}
	return nread, err
}

func (re *RouteEntry) Write(buf []byte) (int, error) {
	var nwrite int
	var err error
	for {
		if nwrite, err = re.conn.Write(buf); err != nil {
			re.restart()
			continue
		}
		break
	}
	return nwrite, err
}

func (re *RouteEntry) Close() {
	re.closechan <- true
	re.restartchan <- true
}
