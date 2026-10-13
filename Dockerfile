FROM golang:1.26.4-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /oauth-server ./cmd/oauth-server

FROM alpine:3.22
RUN apk add --no-cache ca-certificates
COPY --from=build /oauth-server /usr/local/bin/oauth-server
COPY --from=build /src/internal/hashalgo/algo.go /app/internal/hashalgo/algo.go
WORKDIR /app
USER nobody
EXPOSE 8080
ENTRYPOINT ["oauth-server", "-config", "/config/config.yaml"]
