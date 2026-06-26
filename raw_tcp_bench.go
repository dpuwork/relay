package main

import (
	"fmt"
	"io"
	"net"
	"time"
)

func main() {
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	go func() {
		c, _ := l.Accept()
		io.Copy(io.Discard, c)
	}()
	c, _ := net.Dial("tcp", l.Addr().String())
	buf := make([]byte, 32*1024)
	start := time.Now()
	bytes := 0
	for time.Since(start) < 2*time.Second {
		c.Write(buf)
		bytes += len(buf)
	}
	mbps := float64(bytes) / 1024 / 1024 / time.Since(start).Seconds()
	fmt.Printf("Raw Loopback Throughput: %.2f MB/s\n", mbps)
}
