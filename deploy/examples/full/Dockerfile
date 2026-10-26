FROM --platform=$BUILDPLATFORM golang:1.26.10-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# Replace the stock bcrypt hasher before compile. Startup later
# compares this same file with the copy embedded in the binary.
COPY internal/hashalgo/examples/pbkdf2-sha256/algo.go internal/hashalgo/algo.go
ARG TARGETOS
ARG TARGETARCH
ARG TARGETVARIANT
ARG VERSION=0.1.1-pbkdf2
ARG COMMIT=
ARG DATE=
RUN variant="$TARGETVARIANT"; \
    CGO_ENABLED=0 GOOS="$TARGETOS" GOARCH="$TARGETARCH" GOARM="${variant#v}" \
    go build -trimpath \
      -ldflags="-s -w -X github.com/bravo68web/atrium/internal/version.Version=${VERSION} -X github.com/bravo68web/atrium/internal/version.Commit=${COMMIT} -X github.com/bravo68web/atrium/internal/version.Date=${DATE}" \
      -o /atrium ./cmd/atrium \
    && mkdir -p /out/app \
    && chown 65534:65534 /out/app

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build --chown=65534:65534 /atrium /usr/local/bin/atrium
COPY --from=build --chown=65534:65534 /out/app /app
COPY --from=build --chown=65534:65534 /src/internal/hashalgo/algo.go /app/internal/hashalgo/algo.go
WORKDIR /app
USER 65534:65534
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/atrium"]
