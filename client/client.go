package main

import (
	"flag"
	"fmt"
	"github.com/gorilla/websocket"
	"log"
	"net/url"
	"os"
	"os/signal"
	"time"
)

var addr = flag.String("address", "localhost:8080", "http service address")

func main() {
	var msg string

	flag.Parse()
	log.SetFlags(0)
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt)

	u := url.URL{Scheme: "ws", Host: *addr, Path: "/"}
	log.Printf("connecting to %s", u.String())

	c, _, err := websocket.DefaultDialer.Dial(u.String(), nil)
	if err != nil {
		log.Fatal("dial:", err)
	}
	defer func(c *websocket.Conn) {
		err := c.Close()
		if err != nil {

		}
	}(c)

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	log.Println("Connected!")
	log.Println(msg)

	go WaitForOutgoing(c)
	WaitForIncomming(c)

}

func WaitForOutgoing(c *websocket.Conn) {
	for {
		var msg string
		_, err := fmt.Scanln(&msg)
		if err != nil {
			return
		}
		mt := websocket.TextMessage
		err = c.WriteMessage(mt, []byte(msg))
		if err != nil {
			return
		}
	}
}

func WaitForIncomming(c *websocket.Conn) {
	for {
		_, msg, err := ReadMessage(c)
		if err != nil {
			return
		}

		fmt.Println(msg)
	}
}

func ReadMessage(c *websocket.Conn) (int, string, error) {
	mt, p, err := c.ReadMessage()
	if err != nil {
		log.Println(err)
		err := c.Close()
		if err != nil {
			return 0, "", err
		}
		return mt, "", err
	}
	return mt, string(p[:]), nil
}
