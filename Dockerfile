# syntax=docker/dockerfile:1
FROM golang:latest AS build-stage
WORKDIR /build
COPY . .
RUN make

FROM alpine:latest
RUN apk add --no-cache tzdata
WORKDIR /data
COPY --from=build-stage /build/bin /
ENTRYPOINT ["/deceptifeed"]