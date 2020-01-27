FROM golang as builder

LABEL maintainer "Lucas Hild <contact@contact.de>"

ENV GO111MODULE=on

WORKDIR /go/src/app

COPY go.mod .
COPY go.sum .
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -o app cmd/go-ecommerce-api/main.go

FROM alpine

RUN apk add ca-certificates

COPY --from=builder /go/src/app/app /usr/local/bin/app
COPY --from=builder /go/src/app/.env /usr/local/bin/.env

EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/app"]