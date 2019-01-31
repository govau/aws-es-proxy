FROM golang:latest AS builder

COPY . /go/src/github.com/abutaha/aws-es-proxy

# If we don't disable CGO, the binary won't work in the scratch image. Unsure why?
RUN CGO_ENABLED=0 go install github.com/abutaha/aws-es-proxy

#FROM scratch

#COPY --from=builder /go/bin/aws-es-proxy /go/bin/aws-es-proxy
#COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

ENTRYPOINT ["/go/bin/aws-es-proxy"]
