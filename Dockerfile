# syntax=docker/dockerfile:1
FROM golang:latest AS build-stage
WORKDIR /build
COPY . .
RUN make

FROM alpine:latest
WORKDIR /data
COPY --from=build-stage /build/out /
ENTRYPOINT ["/deceptifeed"]