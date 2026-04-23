FROM golang:1.26.2-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /ghmint ./cmd/ghmint

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /ghmint /ghmint

EXPOSE 8080
ENTRYPOINT ["/ghmint"]
