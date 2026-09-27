# The release image: the agentgate binary goreleaser built, on distroless.
# See the Dockerfile at the root for building from source.
FROM gcr.io/distroless/static-debian12:nonroot
ARG TARGETPLATFORM
COPY $TARGETPLATFORM/agentgate /usr/local/bin/agentgate
USER nonroot:nonroot
WORKDIR /home/nonroot
EXPOSE 3333 7777
ENTRYPOINT ["/usr/local/bin/agentgate"]
CMD ["run", "--config", "/etc/agentgate/agentgate.yaml", "--http", ":3333"]
