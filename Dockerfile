# agentgate from source.
#
#   docker build -t agentgate .
#   docker run --rm -v "$PWD:/etc/agentgate" -p 3333:3333 agentgate
#
# The image holds agentgate alone. That is enough for upstreams reached over
# HTTP, for the web UI and for the reporting commands (verify, stats, lock).
# To proxy stdio servers, copy the binary into the image that has them:
#
#   COPY --from=ghcr.io/bnymndev/agentgate:latest /usr/local/bin/agentgate /usr/local/bin/agentgate
FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /agentgate ./cmd/agentgate

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /agentgate /usr/local/bin/agentgate
USER nonroot:nonroot
WORKDIR /home/nonroot
EXPOSE 3333 7777
ENTRYPOINT ["/usr/local/bin/agentgate"]
CMD ["run", "--config", "/etc/agentgate/agentgate.yaml", "--http", ":3333"]
