// XRelay is a utility to forward TCP connections to another server.
// It also supports simple XOR cipher encryption to deceive firewall.
// Copyright 2013, physacco. Distributed under the BSD license.

package main

import (
    "io"
    "fmt"
    "log"
    "net"
    "flag"
    "runtime"
    "github.com/physacco/teleport/common"
)

var (
    LISTEN   string  // listen address, e.g. 0.0.0.0:1080
    BACKEND  string  // backend address, e.g. foo.com:80
    CIPHER   []byte  // XOR cipher key, default is nil
)

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

    if len(CIPHER) > 0 {
        performConnect(frontconn, common.NewXReadWriter(backconn, CIPHER))
    } else {
        performConnect(frontconn, backconn)
    }
}

func performConnect(frontconn, backconn io.ReadWriter) {
    shutdown := make(chan bool, 2)
    go common.IOBridge(frontconn, backconn, shutdown)
    go common.IOBridge(backconn, frontconn, shutdown)

    // wait for either side to close
    <-shutdown
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

const Usage = `Usage: xrelay [Options] LISTEN BACKEND

Options:
    --cipher CIPHER         specify cipher string
    --help                  print this help message and exit
    --version               print the version and exit
`

func Version() string {
    return fmt.Sprintf("xrelay 0.1.0 [%s-%s] (%s)",
        runtime.GOOS, runtime.GOARCH, runtime.Version())
}

func main() {
    cipher := flag.String("cipher", "", "specify cipher string")
    help := flag.Bool("help", false, "print this help message and exit")
    version := flag.Bool("version", false, "print the version and exit")

    flag.Parse()
    CIPHER = []byte(*cipher)

    if *help {
        fmt.Println(Usage)
        return
    }

    if *version {
        fmt.Println(Version())
        return
    }

    args := flag.Args()
    if len(args) < 2 {
        fmt.Println(Usage)
        return
    }

    LISTEN  = args[0]
    BACKEND = args[1]

    ListenAndServe()
}
