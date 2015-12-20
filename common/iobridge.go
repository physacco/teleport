package common

import (
    "io"
    "log"
    "net"
)

func isUseOfClosedConn(err error) bool {
    operr, ok := err.(*net.OpError)
    return ok && operr.Err.Error() == "use of closed network connection"
}


func IOBridge(src io.Reader, dst io.Writer, shutdown chan bool) {
    defer func() {
        shutdown <- true
    }()

    buf := make([]byte, 8192)
    for {
        var reader *io.Reader
        if xrw, ok := src.(XReadWriter); ok {
            reader = &(xrw.XReader.Reader)
        } else {
            reader = &src
        }

        if conn, ok := (*reader).(*net.TCPConn); ok {
            err := conn.SetReadDeadline(AfterSeconds(300))
            if err != nil {
                log.Printf("error SetReadDeadline %s: %s\n", src, err)
                break
            }
        }

        n, err := src.Read(buf)
        if err != nil {
            if !(err == io.EOF || isUseOfClosedConn(err)) {
                log.Printf("error reading %s: %s\n", src, err)
            }
            break
        }

        var writer *io.Writer
        if xrw, ok := dst.(XReadWriter); ok {
            writer = &(xrw.XWriter.Writer)
        } else {
            writer = &dst
        }

        if conn, ok := (*writer).(*net.TCPConn); ok {
            err := conn.SetWriteDeadline(AfterSeconds(120))
            if err != nil {
                log.Printf("error SetWriteDeadline %s: %s\n", dst, err)
                break
            }
        }

        _, err = dst.Write(buf[:n])
        if err != nil {
            log.Printf("error writing %s: %s\n", dst, err)
            break
        }
    }
}
