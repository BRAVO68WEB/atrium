FROM --platform=$BUILDPLATFORM golang:1.26.4-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG TARGETOS
ARG TARGETARCH
ARG TARGETVARIANT
RUN variant="$TARGETVARIANT"; \
    CGO_ENABLED=0 GOOS="$TARGETOS" GOARCH="$TARGETARCH" GOARM="${variant#v}" \
    go build -trimpath -ldflags="-s -w" -o /oauth-server ./cmd/oauth-server

FROM alpine:3.22
RUN apk add --no-cache ca-certificates \
    && mkdir -p /app/internal/hashalgo \
    && chown -R nobody:nobody /app
COPY --from=build --chown=nobody:nobody /oauth-server /usr/local/bin/oauth-server
COPY --from=build --chown=nobody:nobody /src/internal/hashalgo/algo.go /app/internal/hashalgo/algo.go
WORKDIR /app
USER nobody
EXPOSE 8080
ENTRYPOINT ["oauth-server"]
