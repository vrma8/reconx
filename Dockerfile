# Build a static reconx binary. Runtime images deliberately do not include
# offensive third-party scanners; install only approved optional tools in the
# environment where you have assessment authorization.
FROM golang:1.22-bookworm AS build
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/reconx ./cmd/reconx

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/reconx /usr/local/bin/reconx
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/reconx"]
