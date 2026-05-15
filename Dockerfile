FROM golang:1.25-alpine AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY cmd ./cmd
COPY internal ./internal

RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/embyproxy ./cmd/embyproxy

FROM alpine:3.22

RUN apk add --no-cache ca-certificates tzdata

WORKDIR /app

COPY --from=build /out/embyproxy /app/embyproxy
COPY internal/admin/static ./internal/admin/static

RUN mkdir -p /app/data

EXPOSE 8787

CMD ["/app/embyproxy"]
