FROM golang:1.26.2-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

RUN apk add --no-cache upx

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /ghmint ./cmd/ghmint
RUN upx --best /ghmint

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /ghmint /ghmint

EXPOSE 8080
ENTRYPOINT ["/ghmint"]
