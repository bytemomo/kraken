FROM golang:1.25.1-alpine AS builder

RUN apk add --no-cache \
    protobuf-dev \
    gcc \
    bash \
    musl-dev \
    cmake \
    ninja \
    rust \
    cargo \
    openssl-dev \
    perl \
    make \
    libpcap-dev

RUN go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.28 && \
    go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.2

WORKDIR /app

COPY go.work go.work.sum ./
COPY kraken/go.mod kraken/go.sum ./kraken/
COPY trident/go.mod trident/go.sum ./trident/
RUN go mod download

COPY kraken/pkg/moduleabi/ ./kraken/pkg/moduleabi/
COPY modules/protocols/ ./modules/protocols/

# Clean stale build caches from host
RUN find modules/protocols -type d -name build -exec rm -rf {} + 2>/dev/null || true

RUN set -ex && \
    find modules/protocols -name CMakeLists.txt | while read cmakefile; do \
      dir=$(dirname "$cmakefile") && \
      echo "==> Building $dir" && \
      cmake -S "$dir" -B "$dir/build" -G Ninja -DCMAKE_BUILD_TYPE=Release && \
      cmake --build "$dir/build" --config Release ; \
    done

RUN cd modules/protocols/tls/abi/cert_inspect && cargo build --release

COPY kraken/pkg/modulepb/ ./kraken/pkg/modulepb/
RUN cd kraken/pkg/modulepb && go generate

COPY kraken/ ./kraken/
COPY trident/ ./trident/

RUN CGO_ENABLED=1 GOOS=linux go build -o /kraken ./kraken

# Final stage
FROM alpine:latest

RUN apk add --no-cache \
    nmap \
    nmap-scripts \
    libgcc \
    musl \
    openssl-dev \
    libpcap \
    python3 \
    py3-pip \
    graphviz \
    gcc \
    python3-dev \
    musl-dev \
    linux-headers

COPY modules/protocols/mqtt/container/boofuzz/requirements.txt /tmp/requirements.txt
RUN pip3 install --no-cache-dir --break-system-packages -r /tmp/requirements.txt && \
    rm /tmp/requirements.txt && \
    apk del gcc python3-dev musl-dev linux-headers

COPY --from=builder /kraken /kraken
COPY --from=builder /app/modules /modules

ENTRYPOINT ["/kraken"]
