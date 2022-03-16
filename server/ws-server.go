package main

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
)

const bufferSize = 4096

var sockets []Websocket

type Websocket struct {
	conn   net.Conn
	bufrw  *bufio.ReadWriter
	header http.Header
	status uint16
	name   string
}

type Frame struct {
	Length  uint64
	Mask    []byte
	Payload []byte
}

func main() {
	http.HandleFunc("/", IndexHandler)
	log.Fatal(http.ListenAndServe(*address, nil))
}

var address = flag.String("address", "localhost:8080", "http address")

func IndexHandler(w http.ResponseWriter, req *http.Request) {
	websocket, err := InitWebsocket(w, req)
	check(err)
	sockets = append(sockets, *websocket)

	err = websocket.Handshake()
	check(err)

	for {
		frame := Frame{}
		frame, err = websocket.Recv()
		if string(frame.Payload) == "EXIT" {
			err = websocket.Close()
			check(err)
		}
		SendToAll(frame, websocket)
	}
}

func SendToAll(frame Frame, sender *Websocket) {
	for i := 0; i < len(sockets); i++ {
		if sockets[i].conn != sender.conn {
			err := sockets[i].Send(frame)
			check(err)
		}
	}
}

// InitWebsocket initiates an open websocket connection.
func InitWebsocket(w http.ResponseWriter, req *http.Request) (*Websocket, error) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "webserver doesn't support hijacking", http.StatusInternalServerError)
	}

	conn, bufrw, err := hj.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	return &Websocket{conn, bufrw, req.Header, 1000, "Socket " + strconv.Itoa(len(sockets)+1) + ": "}, nil
}

// Handshake Does initial handshake without closing.
func (ws *Websocket) Handshake() error {
	hash := getAcceptHash(ws.header.Get("Sec-WebSocket-Key"))
	lines := []string{
		"HTTP/1.1 101 Switching Protocols",
		"Upgrade: WebSocket",
		"Connection: Upgrade",
		"Sec-WebSocket-Accept: " + hash,
		"", //  Two spaces to signalize that header is finished.
		"",
	}

	// Send Header
	if _, err := ws.bufrw.Write([]byte(strings.Join(lines, "\r\n"))); err != nil {
		return err
	}
	return ws.bufrw.Flush()
}

func (ws *Websocket) Recv() (Frame, error) {
	frame := Frame{}

	// Extract head and mask bytes
	head, err := ws.read(2)
	if err != nil {
		return frame, err
	}

	frame.Mask, err = ws.read(4)
	if err != nil {
		return frame, err
	}

	// Extract length of payload
	frame.Length = uint64(head[1] & 0x7F)
	if frame.Length > 125 {
		return frame, errors.New("message is too long")
	}

	// Extract payload
	frame.Payload, err = ws.read(int(frame.Length))
	if err != nil {
		return frame, err
	}

	for i := uint64(0); i < frame.Length; i++ {
		frame.Payload[i] ^= frame.Mask[i%4]
	}

	return frame, err
}

func (ws *Websocket) read(size int) ([]byte, error) {
	data := make([]byte, 0)
	for {
		if len(data) == size {
			break
		}
		// Temporary slice to read chunk
		sz := bufferSize
		remaining := size - len(data)
		if sz > remaining {
			sz = remaining
		}
		temp := make([]byte, sz)

		n, err := ws.bufrw.Read(temp)
		if err != nil && err != io.EOF {
			return data, err
		}

		data = append(data, temp[:n]...)
	}
	fmt.Println(data)
	return data, nil
}

func (ws *Websocket) Send(frame Frame) error {
	// Set type of message - 1000 0001 - text
	data := make([]byte, 2)
	data[0] = 0x81

	// Add name of sender
	byteName := []byte(ws.name)
	frame.Payload = append(byteName, frame.Payload...)
	frame.Length += uint64(len(byteName))

	// Add length of payload
	data[1] = byte(frame.Length)
	data = append(data, frame.Payload...)

	return ws.write(data)
}

func (ws *Websocket) write(data []byte) error {
	if _, err := ws.bufrw.Write(data); err != nil {
		return err
	}
	return ws.bufrw.Flush()
}

// Close closes tcp connection and ends handshake
func (ws *Websocket) Close() error {

	// Fill this with closing code.
	return ws.conn.Close()
}

// Check documentation on this
func getAcceptHash(key string) string {
	h := sha1.New()
	h.Write([]byte(key))
	h.Write([]byte("258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func check(err error) {
	if err != nil {
		log.Fatalln(err)
	}
}
