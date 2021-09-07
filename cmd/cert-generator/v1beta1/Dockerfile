# Build the Katib DB manager.
FROM golang:alpine AS build-env

WORKDIR /go/src/github.com/kubeflow/katib

# Download packages.
COPY go.mod .
COPY go.sum .
RUN go mod download -x

# Copy sources.
COPY cmd/ cmd/
COPY pkg/ pkg/

# Build the binary.
RUN if [ "$(uname -m)" = "ppc64le" ]; then \
    CGO_ENABLED=0 GOOS=linux GOARCH=ppc64le go build -a -o katib-cert-generator ./cmd/cert-generator/v1beta1; \
    elif [ "$(uname -m)" = "aarch64" ]; then \
    CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -a -o katib-cert-generator ./cmd/cert-generator/v1beta1; \
    else \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -o katib-cert-generator ./cmd/cert-generator/v1beta1; \
    fi

# Copy the cert-generator into a thin image.
FROM alpine:3.14.2
WORKDIR /app
COPY --from=build-env /go/src/github.com/kubeflow/katib/katib-cert-generator /app/
#ENTRYPOINT ["./katib-cert-generator", "generate"]
