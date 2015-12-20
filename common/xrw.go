package common

import (
    "io"
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

func NewXReadWriter(rdwtr io.ReadWriter, cipher []byte) XReadWriter {
    reader := XReader{Reader: rdwtr, Cipher: cipher}
    writer := XWriter{Writer: rdwtr, Cipher: cipher}
    return XReadWriter{&reader, &writer}
}
