FROM golang:1.23-alpine AS builder

# Enable automatic toolchain downloading
ENV GOTOOLCHAIN=auto

WORKDIR /build

# Copy ezauth library (root context)
COPY go.mod go.sum ./
COPY pkg/ ./pkg/
COPY ezauth.go ./

# Prepare example directory
WORKDIR /build/_example
COPY _example/go.mod _example/go.sum ./

# Download dependencies
# We need to run tidy/download inside _example, but since it depends on ../,
# go mod will look at ../go.mod.
RUN go mod download

COPY _example/main.go ./
COPY _example/static/ ./static/

# Build
RUN go build -o example-app main.go

FROM alpine:latest
WORKDIR /app
COPY --from=builder /build/_example/example-app .

EXPOSE 8080
CMD ["./example-app"]
