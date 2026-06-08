FROM golang:1.26.4-alpine AS build

WORKDIR /src

ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILT_AT=unknown

COPY go.mod go.sum ./
RUN go mod download

COPY cmd ./cmd
COPY internal ./internal

RUN CGO_ENABLED=0 GOOS=linux go build -trimpath \
    -ldflags="-s -w -X embyproxy/internal/buildinfo.Version=${VERSION} -X embyproxy/internal/buildinfo.Commit=${COMMIT} -X embyproxy/internal/buildinfo.BuiltAt=${BUILT_AT}" \
    -o /out/embyproxy ./cmd/embyproxy

FROM alpine:3.23

RUN apk add --no-cache ca-certificates tzdata

ENV TZ=Asia/Shanghai

WORKDIR /app

COPY --from=build /out/embyproxy /app/embyproxy

RUN mkdir -p /app/data

EXPOSE 8787

CMD ["/app/embyproxy"]
