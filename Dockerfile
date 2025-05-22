# syntax=docker/dockerfile:1
FROM golang:latest AS build-stage
WORKDIR /build
COPY . .
RUN git update-index -q --refresh
RUN make clean build

FROM alpine:latest
RUN apk add --no-cache tzdata
WORKDIR /data
COPY --from=build-stage /build/bin /
ENTRYPOINT ["/deceptifeed"]