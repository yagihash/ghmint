FROM golang:1.26.2-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

RUN apk add --no-cache upx

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s" -o /ghmint ./cmd/ghmint
RUN upx --best /ghmint

FROM alpine:3.21

COPY --from=builder /ghmint /ghmint

USER nobody
EXPOSE 8080
ENTRYPOINT ["/ghmint"]
