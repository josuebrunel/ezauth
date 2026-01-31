FROM golang:1.25-alpine AS builder

WORKDIR /app

# Copy the EzAuth library source
# In a real scenario, this would be a go get, but here we mount/copy the local files
# Since we are inside the repository, we need to copy the context correctly.
# However, usually docker build is run from the root of the repo for this to work.
# Assuming user runs docker-compose from _example/go-server, we need to handle the parent dir.
# But docker build context restrictions apply.
# 
# Simplest approach for the example: 
# Rely on go.mod pointing to local replace, invalid in pure docker build unless we copy everything.
#
# Let's assume the user will run this from the project root? 
# "In _example/go-server can you add a docker compose" implies running it there.
#
# If running from _example/go-server, we can't easily copy ../../pkg without context tweaks.
# 
# Workaround: Use a simple run compatible with 'go run' if we map volumes, 
# OR use a Dockerfile that expects the build context to be the project root.
# 
# Let's write a Dockerfile that assumes build context is PROJECT ROOT.

COPY . .

# Build the example
WORKDIR /app/_example/go-server
RUN go build -o main .

FROM alpine:latest
WORKDIR /app
COPY --from=builder /app/_example/go-server/main .
COPY --from=builder /app/_example/go-server/views ./views

# Expose port
EXPOSE 3000

CMD ["./main"]
