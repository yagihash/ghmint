FROM golang:1.26.2-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

RUN apk add --no-cache upx

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s" -o /mini-gh-sts ./cmd/mini-gh-sts
RUN upx --best /mini-gh-sts

FROM alpine:3.21

COPY --from=builder /mini-gh-sts /mini-gh-sts

USER nobody
EXPOSE 8080
ENTRYPOINT ["/mini-gh-sts"]
