FROM golang

ARG github_tag=master
ENV repo_location=/tmp/wattson

RUN go get gopkg.in/alecthomas/kingpin.v2
RUN go get github.com/dghubble/sling
RUN git clone https://github.com/indigo-dc/wattson -b $github_tag $repo_location

RUN CGO_ENABLED=0 GOOS=linux go build -a -v -o /usr/bin/wattson $repo_location/wattson.go

ENTRYPOINT ["/usr/bin/wattson"]
CMD ["--help"]
