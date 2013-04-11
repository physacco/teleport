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
)

var (
    LISTEN   string  // listen address, e.g. 0.0.0.0:1080
    BACKEND  string  // backend address, e.g. foo.com:80
    CIPHER   []byte  // XOR cipher key, default is nil
)

type XReader struct {
    io.Reader
    Cipher []byte
    Position uint64
}

func (rdr *XReader) Read(p []byte) (n int, err error) {
    n, err = rdr.Reader.Read(p)
    keylen := uint64(len(rdr.Cipher))
    if keylen > 0 {
        for i := 0; i < n; i++ {
            keypos := rdr.Position % keylen
            p[i] ^= rdr.Cipher[keypos]
            rdr.Position += 1
        }
    }
    return
}

type XWriter struct {
    io.Writer
    Cipher []byte
    Position uint64
}

func (wtr *XWriter) Write(p []byte) (n int, err error) {
    plen := len(p)
    buf := make([]byte, plen)
    keylen := uint64(len(wtr.Cipher))
    if keylen > 0 {
        for i := 0; i < plen; i++ {
            keypos := wtr.Position % keylen
            buf[i] = p[i] ^ wtr.Cipher[keypos]
            wtr.Position += 1
        }
    }
    n, err = wtr.Writer.Write(buf)
    return
}

type XReadWriter struct {
    *XReader
    *XWriter
}

func newXReadWriter(rdwtr io.ReadWriter, cipher []byte) XReadWriter {
    reader := XReader{Reader: rdwtr, Cipher: cipher}
    writer := XWriter{Writer: rdwtr, Cipher: cipher}
    return XReadWriter{&reader, &writer}
}

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

    if len(CIPHER) > 0 {
        performConnect(frontconn, newXReadWriter(backconn, CIPHER))
    } else {
        performConnect(frontconn, backconn)
    }
}

func performConnect(frontconn, backconn io.ReadWriter) {
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
