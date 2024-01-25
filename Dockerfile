FROM golang:1.21.6-bookworm AS build

ARG VERSION

WORKDIR /go/src/knubbis-fleetlock
COPY . .

RUN go mod download
RUN go test -race ./...
RUN CGO_ENABLED=0 go build -ldflags="-X github.com/SUNET/knubbis-fleetlock/server.version=$VERSION" -o /go/bin/knubbis-fleetlock

FROM gcr.io/distroless/static-debian11:nonroot
COPY --from=build /go/bin/knubbis-fleetlock /
CMD ["/knubbis-fleetlock", "server", "--config", "/conf/knubbis-fleetlock.toml"]
