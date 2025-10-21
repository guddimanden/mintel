package main

import (
	"net"
	"time"
)

type Bot struct {
	uid     int
	conn    net.Conn
	version byte
	source  string
}

func NewBot(conn net.Conn, version byte, source string) *Bot {
	return &Bot{-1, conn, version, source}
}

func (this *Bot) Handle() {
	verBuf := make([]byte, 1)
	this.conn.SetReadDeadline(time.Now().Add(2 * time.Second))

	n, err := this.conn.Read(verBuf)
	if err != nil || n != 1 {
		this.version = 0
	} else {
		this.version = verBuf[0]
	}
	clientList.AddClient(this)
	defer clientList.DelClient(this)

	buf := make([]byte, 2)
	for {
		this.conn.SetDeadline(time.Now().Add(180 * time.Second))
		if n, err := this.conn.Read(buf); err != nil || n != len(buf) {
			return
		}
		if n, err := this.conn.Write(buf); err != nil || n != len(buf) {
			return
		}
	}
}

func (this *Bot) QueueBuf(buf []byte) {
	this.conn.Write(buf)
}
