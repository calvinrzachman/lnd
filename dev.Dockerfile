# If you change this please also update GO_VERSION in Makefile (then run
# `make lint` to see where else it needs to be updated as well).
FROM golang:1.26.3-alpine AS builder

LABEL maintainer="Olaoluwa Osuntokun <laolu@lightning.engineering>"

# Force Go to use the cgo based DNS resolver. This is required to ensure DNS
# queries required to connect to linked containers succeed.
ENV GODEBUG netdns=cgo

# Install dependencies.
RUN apk add --no-cache --update alpine-sdk \
    bash \
    git \
    make 

# Copy in the local repository to build from.
COPY . /go/src/github.com/lightningnetwork/lnd

#  Install/build lnd.
# BUILD_TAGS selects the Go build tags. Default includes `switchrpc`; override
# with `--build-arg BUILD_TAGS="..."` (omit switchrpc for a tag-off build).
ARG BUILD_TAGS="autopilotrpc signrpc switchrpc walletrpc chainrpc invoicesrpc watchtowerrpc neutrinorpc monitoring peersrpc kvdb_postgres kvdb_etcd kvdb_sqlite"
RUN cd /go/src/github.com/lightningnetwork/lnd \
    &&  make \
    # NOTE(calvin): This build contains `switchrpc`, for use with the external
    # router (payment service). Only a *single* router may dispatch at a time.
    # A switchrpc build refuses the local payment-sending RPCs by default, so
    # the embedded router cannot collide with the external one; pass
    # --enable-local-payment-dispatch to override that. Allow all in-flight
    # attempts to complete before swapping back to a local-router build.
    &&  make install-all tags="${BUILD_TAGS}"

# Start a new, final image to reduce size.
FROM alpine AS final

# Expose lnd ports (server, rpc).
EXPOSE 9735 10009

# Copy the binaries and entrypoint from the builder image.
COPY --from=builder /go/bin/lncli /bin/
COPY --from=builder /go/bin/lnd /bin/

# Add bash.
RUN apk add --no-cache \
    bash

# Copy the entrypoint script.
COPY "docker/lnd/start-lnd.sh" .
RUN chmod +x start-lnd.sh
