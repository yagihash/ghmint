FROM golang:1.26.3-alpine@sha256:91eda9776261207ea25fd06b5b7fed8d397dd2c0a283e77f2ab6e91bfa71079d AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

RUN apk add --no-cache upx

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /ghmint ./cmd/ghmint
RUN upx --best /ghmint

FROM gcr.io/distroless/static-debian12:nonroot@sha256:d093aa3e30dbadd3efe1310db061a14da60299baff8450a17fe0ccc514a16639

COPY --from=builder /ghmint /ghmint

EXPOSE 8080
ENTRYPOINT ["/ghmint"]
