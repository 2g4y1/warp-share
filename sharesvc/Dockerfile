# syntax=docker/dockerfile:1

FROM golang:1.25-alpine AS build
WORKDIR /src

RUN apk add --no-cache ca-certificates

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/warp-share ./cmd/sharesvc && \
    CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/warp-admin ./cmd/sharesvc-admin

FROM alpine:3.23
RUN apk add --no-cache ca-certificates su-exec

# Match the common PUID/PGID=1000 pattern used by other services here.
RUN addgroup -g 1000 -S sharesvc && adduser -u 1000 -S -G sharesvc sharesvc

COPY --from=build /out/warp-share /usr/local/bin/warp-share
COPY --from=build /out/warp-admin /usr/local/bin/warp-admin
COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

EXPOSE 8080
ENTRYPOINT ["/docker-entrypoint.sh"]
