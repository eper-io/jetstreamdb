FROM golang:1.19.3

ADD . /go/src

WORKDIR /go/src

CMD go run main.go
