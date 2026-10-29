FROM golang:1.27-alpine AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 go build -o main

FROM alpine

WORKDIR /app

COPY --from=builder /src/main .
COPY --from=builder /src/templates ./templates
COPY --from=builder /src/static ./static

ENV DB_PATH=/data/app.db
VOLUME /data

EXPOSE 3000

CMD ["./main"]
