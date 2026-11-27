# Build stage: compile a static binary.
FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .

# VERSION is stamped into the binary; CI passes the release tag (vX.Y.Z).
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/stackctl ./cmd/stackctl

# Runtime: a small image that already contains the Docker CLI and the Compose
# plugin, which stackctl shells out to (see README for the minimum version).
FROM docker:cli
COPY --from=build /out/stackctl /usr/local/bin/stackctl

# Run as a non-root user. Access to the Docker socket is granted at deploy
# time by adding the host 'docker' group to the container user via
#   group_add: ["988"]   # GID from: getent group docker | cut -d: -f3
# (see compose.example.yaml). Giving a container Docker socket access is
# equivalent to giving it root on the host - read the README before exposing.
RUN adduser -D -u 1000 stackctl
USER stackctl

EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/stackctl"]
