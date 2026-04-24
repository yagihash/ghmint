FROM golang:1.26.2-alpine@sha256:f85330846cde1e57ca9ec309382da3b8e6ae3ab943d2739500e08c86393a21b1 AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

RUN apk add --no-cache upx

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /ghmint ./cmd/ghmint
RUN upx --best /ghmint

FROM gcr.io/distroless/static-debian12:nonroot@sha256:a9329520abc449e3b14d5bc3a6ffae065bdde0f02667fa10880c49b35c109fd1

COPY --from=builder /ghmint /ghmint

EXPOSE 8080
ENTRYPOINT ["/ghmint"]
