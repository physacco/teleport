teleport
========

A set of tools for easily transporting data over networks

## Installation

It is assumed that you have set [GOPATH](https://github.com/golang/go/wiki/GOPATH) in your environment and added `$GOPATH/bin` to your **PATH**. Then you can use the following command to automatically download, compile and install this software:

    # install the SOCKS5 server
    go get github.com/physacco/teleport/xsocks5

    # install the relayer
    go get github.com/physacco/teleport/xrelay

The newly compiled executables (_xsocks5[.exe]_, _xrelay[.exe]_) will be placed in your `$GOPATH/bin` directory.

