// XRelay is a utility to forward TCP connections to another server.
// It also supports simple XOR cipher encryption to deceive firewall.
// Copyright 2013, physacco. Distributed under the BSD license.

package main

import (
    "io"
    "os"
    "fmt"
    "log"
    "net"
    "strconv"
)

var (
    LISTEN   string  // listen address, e.g. 0.0.0.0:1080
    BACKEND  string  // backend address, e.g. foo.com:80
    CIPHER   uint8   // XOR cipher key, default 0
)

func isUseOfClosedConn(err error) bool {
    operr, ok := err.(*net.OpError)
    return ok && operr.Err.Error() == "use of closed network connection"
}

func iobridge(src io.Reader, dst io.Writer, shutdown chan bool) {
    defer func() {
        shutdown <- true
    }()

    buf := make([]byte, 8192)
    for {
        n, err := src.Read(buf)
        if err != nil {
            if !(err == io.EOF || isUseOfClosedConn(err)) {
                log.Printf("error reading %s: %s\n", src, err)
            }
            break
        }

        if CIPHER != 0 {
            for i := 0; i < n; i++ {
                buf[i] ^= CIPHER
            }
        }

        _, err = dst.Write(buf[:n])
        if err != nil {
            log.Printf("error writing %s: %s\n", dst, err)
            break
        }
    }
}

func handleConnection(frontconn net.Conn) {
    frontaddr := frontconn.RemoteAddr().String()
    log.Println("ACCEPTED frontend", frontconn, frontaddr)
    defer func() {
        if err := recover(); err != nil {
            log.Println("ERROR frontend", frontconn, frontaddr, err)
        }
        frontconn.Close()
        log.Println("DISCONNECTED frontend", frontconn, frontaddr)
    }()

    log.Printf("trying to connect to %s...\n", BACKEND)
    backconn, err := net.Dial("tcp", BACKEND)
    if err != nil {
        log.Printf("failed to connect to %s: %s\n", BACKEND, err)
        return
    }

    backaddr := backconn.RemoteAddr().String()
    log.Println("CONNECTED backend", backconn, backaddr)
    defer func() {
        backconn.Close()
        log.Println("DISCONNECTED backend", backconn, backaddr)
    }()

    shutdown := make(chan bool)
    go iobridge(frontconn, backconn, shutdown)
    go iobridge(backconn, frontconn, shutdown)

    // wait for either side to close
    select {
    case <-shutdown:
        return
    }
}

func ListenAndServe() {
    listener, err := net.Listen("tcp", LISTEN)
    if err != nil {
        log.Fatal("Listen error: ", err)
    }
    log.Printf("Listening on %s...\n", LISTEN)

    for {
        conn, err := listener.Accept()
        if err != nil {
            log.Println("Accept error:", err)
            continue
        }
        go handleConnection(conn)
    }
}

func main() {
    if len(os.Args) < 3 {
        fmt.Println("Usage: xrelay LISTEN BACKEND [CIPHER]")
        return
    }

    LISTEN  = os.Args[1]
    BACKEND = os.Args[2]

    if len(os.Args) > 3 {
        cipher, err := strconv.Atoi(os.Args[3])
        if err != nil {
            log.Fatal("Invalid cipher key")
        }
        CIPHER = uint8(cipher)
    }

    ListenAndServe()
}
