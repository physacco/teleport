
##
PREFIX = /usr

##
EXES = xrelay xsocks5
BINS = ${EXES:%=bin/%}

# clear out all suffixes
.SUFFIXES:
# list only those we use
.SUFFIXES: .go
# define a suffix rule for .go
bin/%: src/%.go
	go build -o $@ $<

##
.PHONY: all compile install clean

all: compile

compile: ${BINS}

install: compile
	install -d ${PREFIX}/bin
	install -m 755 ${BINS} ${PREFIX}/bin

clean:
	rm -f ${BINS}
