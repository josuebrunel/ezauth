# Installation

Depending on how you intend to use `ezauth`, there are different ways to install it.

## As a Library

To use `ezauth` as a library in your Go project, you can use `go get`:

```bash
go get github.com/josuebrunel/ezauth
```

## As a Standalone Service

If you want to run `ezauth` as a service, you can clone the repository and build the binary:

```bash
git clone https://github.com/josuebrunel/ezauth.git
cd ezauth
go build -o ezauthapi ./cmd/ezauthapi
```

Alternatively, you can run it using Docker:

```bash
docker-compose up -d
```
