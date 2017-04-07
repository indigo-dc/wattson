FROM indigodatacloud/ci-images:go

RUN go get gopkg.in/alecthomas/kingpin.v2
RUN go get github.com/dghubble/sling
RUN CGO_ENABLED=0 GOOS=linux go build -a -v -o $WATTSON ${GOPATH}/wattson.go

ADD wattson /
ADD ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
ENTRYPOINT ["/wattson"]
CMD ["--help"]
