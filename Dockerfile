ARG GO_VERSION=""
FROM golang:${GO_VERSION}alpine AS builder
WORKDIR /src
COPY go.* /src/
RUN go mod download
COPY . /src
RUN go build -o bin/api-reconcilers ./cmd/api-reconcilers

FROM gcr.io/distroless/base
WORKDIR /app
COPY --from=builder /src/bin/api-reconcilers /app/api-reconcilers
ENTRYPOINT ["/app/api-reconcilers"]
