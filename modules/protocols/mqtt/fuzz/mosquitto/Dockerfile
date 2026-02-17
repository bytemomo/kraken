# Mosquitto MQTT Fuzzer - AFL++ LTO with ASan/UBSan
# Standalone Dockerfile - clones mosquitto v2.1.0
# Uses LTO mode for collision-free coverage and auto-dictionary extraction
#
# Build: docker build -t mosquitto-fuzz .
# Run:   docker run --rm -it -v ./output:/work/output mosquitto-fuzz fuzz connect

FROM docker.io/aflplusplus/aflplusplus:stable AS builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    build-essential git libssl-dev pkg-config \
    ca-certificates libcjson-dev xsltproc docbook-xsl && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

WORKDIR /work

# Clone mosquitto source
ARG MOSQUITTO_VERSION=v2.1.0
RUN git clone --depth 1 --branch ${MOSQUITTO_VERSION} \
    https://github.com/eclipse-mosquitto/mosquitto.git

# Copy harnesses and mutators
COPY fuzz/mosquitto/harness_packet_read.c /work/mosquitto/
COPY fuzz/mosquitto/harness_broker_connect.c /work/mosquitto/
COPY fuzz/mosquitto/harness_broker_publish.c /work/mosquitto/
COPY fuzz/mosquitto/harness_broker_subscribe.c /work/mosquitto/
COPY fuzz/mosquitto/harness_property_parse.c /work/mosquitto/
COPY fuzz/mosquitto/repro.c /work/mosquitto/
COPY fuzz/mosquitto/mutator_connect.c /work/mosquitto/
COPY fuzz/mosquitto/mutator_property.c /work/mosquitto/
COPY fuzz/mosquitto/mutator_publish.c /work/mosquitto/
COPY fuzz/mosquitto/mutator_subscribe.c /work/mosquitto/

# Build mosquitto with AFL++ LTO instrumentation
# WITH_FUZZING=yes builds mosquitto_broker.a instead of the executable
# Only build libcommon, lib, and src - skip apps, client, plugins
# Disable HTTP_API to avoid microhttpd dependency
# LTO requires matching LLVM version ar/ranlib - use AFL++ bundled ones
RUN cd mosquitto && \
    make -C libcommon -j$(nproc) \
    CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    AR=llvm-ar-19 \
    RANLIB=llvm-ranlib-19 \
    CFLAGS="-O2 -g -flto -fno-omit-frame-pointer -fsanitize=address,undefined -fno-sanitize-recover=all -fPIC" \
    CXXFLAGS="-O2 -g -flto -fno-omit-frame-pointer -fsanitize=address,undefined -fno-sanitize-recover=all -fPIC" \
    LDFLAGS="-flto -fsanitize=address,undefined" \
    WITH_FUZZING=yes \
    WITH_TLS=yes \
    WITH_WEBSOCKETS=yes \
    WITH_HTTP_API=no && \
    make -C lib -j$(nproc) \
    CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    AR=llvm-ar-19 \
    RANLIB=llvm-ranlib-19 \
    CFLAGS="-O2 -g -flto -fno-omit-frame-pointer -fsanitize=address,undefined -fno-sanitize-recover=all -fPIC" \
    CXXFLAGS="-O2 -g -flto -fno-omit-frame-pointer -fsanitize=address,undefined -fno-sanitize-recover=all -fPIC" \
    LDFLAGS="-flto -fsanitize=address,undefined" \
    WITH_FUZZING=yes \
    WITH_TLS=yes \
    WITH_WEBSOCKETS=yes \
    WITH_HTTP_API=no && \
    make -C src -j$(nproc) \
    CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    AR=llvm-ar-19 \
    RANLIB=llvm-ranlib-19 \
    CFLAGS="-O2 -g -flto -fno-omit-frame-pointer -fsanitize=address,undefined -fno-sanitize-recover=all -fPIC" \
    CXXFLAGS="-O2 -g -flto -fno-omit-frame-pointer -fsanitize=address,undefined -fno-sanitize-recover=all -fPIC" \
    LDFLAGS="-flto -fsanitize=address,undefined" \
    WITH_FUZZING=yes \
    WITH_TLS=yes \
    WITH_WEBSOCKETS=yes \
    WITH_HTTP_API=no

# Build fuzzers with AFL++ LTO
# AFL_LLVM_LTO_AUTODICTIONARY=1 extracts strings from comparisons automatically
# 1. Client-side packet read fuzzer
RUN cd /work/mosquitto && \
    AFL_LLVM_LTO_AUTODICTIONARY=1 afl-clang-lto \
    -O2 -g -flto -fno-omit-frame-pointer \
    -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=all \
    -I/work/mosquitto \
    -I/work/mosquitto/lib \
    -I/work/mosquitto/include \
    -I/work/mosquitto/libcommon \
    /work/mosquitto/harness_packet_read.c \
    -Wl,--whole-archive \
    /work/mosquitto/lib/libmosquitto.a \
    /work/mosquitto/libcommon/libmosquitto_common.a \
    -Wl,--no-whole-archive \
    -lssl -lcrypto -lcjson -lpthread \
    -o /work/fuzz_packet_read

# 2. Broker CONNECT handler fuzzer
RUN cd /work/mosquitto && \
    AFL_LLVM_LTO_AUTODICTIONARY=1 afl-clang-lto \
    -O2 -g -flto -fno-omit-frame-pointer \
    -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=all \
    -DWITH_BROKER -DWITH_TLS -DWITH_TLS_PSK -DWITH_PERSISTENCE -DWITH_MEMORY_TRACKING \
    -DWITH_BRIDGE -DWITH_EPOLL -DWITH_SYS_TREE -DWITH_CONTROL \
    -DWITH_UNIX_SOCKETS -DWITH_WEBSOCKETS=WS_IS_BUILTIN \
    -I/work/mosquitto \
    -I/work/mosquitto/src \
    -I/work/mosquitto/lib \
    -I/work/mosquitto/include \
    -I/work/mosquitto/common \
    -I/work/mosquitto/deps \
    -I/work/mosquitto/libcommon \
    /work/mosquitto/harness_broker_connect.c \
    /work/mosquitto/src/mosquitto_broker.a \
    -Wl,--whole-archive /work/mosquitto/libcommon/libmosquitto_common.a -Wl,--no-whole-archive \
    -lssl -lcrypto -lcjson -lpthread -lm -ldl \
    -o /work/fuzz_broker_connect

# 3. Broker PUBLISH handler fuzzer
RUN cd /work/mosquitto && \
    AFL_LLVM_LTO_AUTODICTIONARY=1 afl-clang-lto \
    -O2 -g -flto -fno-omit-frame-pointer \
    -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=all \
    -DWITH_BROKER -DWITH_TLS -DWITH_TLS_PSK -DWITH_PERSISTENCE -DWITH_MEMORY_TRACKING \
    -DWITH_BRIDGE -DWITH_EPOLL -DWITH_SYS_TREE -DWITH_CONTROL \
    -DWITH_UNIX_SOCKETS -DWITH_WEBSOCKETS=WS_IS_BUILTIN \
    -I/work/mosquitto \
    -I/work/mosquitto/src \
    -I/work/mosquitto/lib \
    -I/work/mosquitto/include \
    -I/work/mosquitto/common \
    -I/work/mosquitto/deps \
    -I/work/mosquitto/libcommon \
    /work/mosquitto/harness_broker_publish.c \
    /work/mosquitto/src/mosquitto_broker.a \
    -Wl,--whole-archive /work/mosquitto/libcommon/libmosquitto_common.a -Wl,--no-whole-archive \
    -lssl -lcrypto -lcjson -lpthread -lm -ldl \
    -o /work/fuzz_broker_publish

# 4. Broker SUBSCRIBE handler fuzzer
RUN cd /work/mosquitto && \
    AFL_LLVM_LTO_AUTODICTIONARY=1 afl-clang-lto \
    -O2 -g -flto -fno-omit-frame-pointer \
    -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=all \
    -DWITH_BROKER -DWITH_TLS -DWITH_TLS_PSK -DWITH_PERSISTENCE -DWITH_MEMORY_TRACKING \
    -DWITH_BRIDGE -DWITH_EPOLL -DWITH_SYS_TREE -DWITH_CONTROL \
    -DWITH_UNIX_SOCKETS -DWITH_WEBSOCKETS=WS_IS_BUILTIN \
    -I/work/mosquitto \
    -I/work/mosquitto/src \
    -I/work/mosquitto/lib \
    -I/work/mosquitto/include \
    -I/work/mosquitto/common \
    -I/work/mosquitto/deps \
    -I/work/mosquitto/libcommon \
    /work/mosquitto/harness_broker_subscribe.c \
    /work/mosquitto/src/mosquitto_broker.a \
    -Wl,--whole-archive /work/mosquitto/libcommon/libmosquitto_common.a -Wl,--no-whole-archive \
    -lssl -lcrypto -lcjson -lpthread -lm -ldl \
    -o /work/fuzz_broker_subscribe

# 5. Property parsing fuzzer (MQTT 5.0 properties)
RUN cd /work/mosquitto && \
    AFL_LLVM_LTO_AUTODICTIONARY=1 afl-clang-lto \
    -O2 -g -flto -fno-omit-frame-pointer \
    -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=all \
    -I/work/mosquitto \
    -I/work/mosquitto/lib \
    -I/work/mosquitto/include \
    -I/work/mosquitto/libcommon \
    /work/mosquitto/harness_property_parse.c \
    -Wl,--whole-archive \
    /work/mosquitto/lib/libmosquitto.a \
    /work/mosquitto/libcommon/libmosquitto_common.a \
    -Wl,--no-whole-archive \
    -lssl -lcrypto -lcjson -lpthread \
    -o /work/fuzz_property_parse

# 6. Build custom mutators (use plain clang, not afl-clang-fast)
RUN cd /work/mosquitto && \
    clang -shared -fPIC -O2 -Wall \
    /work/mosquitto/mutator_connect.c \
    -o /work/mutator_connect.so && \
    clang -shared -fPIC -O2 -Wall \
    /work/mosquitto/mutator_property.c \
    -o /work/mutator_property.so && \
    clang -shared -fPIC -O2 -Wall \
    /work/mosquitto/mutator_publish.c \
    -o /work/mutator_publish.so && \
    clang -shared -fPIC -O2 -Wall \
    /work/mosquitto/mutator_subscribe.c \
    -o /work/mutator_subscribe.so

# ============================================================================ #
#                  TRIAGE BUILD (non-AFL, pure ASan/UBSan)                     #
# ============================================================================ #

# Clean and rebuild without AFL for triage
RUN cd mosquitto && \
    make -C libcommon clean && make -C lib clean && make -C src clean && \
    make -C libcommon -j$(nproc) \
    CC=clang \
    CXX=clang++ \
    CFLAGS="-O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined -fno-sanitize-recover=all -fPIC" \
    CXXFLAGS="-O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined -fno-sanitize-recover=all -fPIC" \
    LDFLAGS="-fsanitize=address,undefined" \
    WITH_FUZZING=yes \
    WITH_TLS=yes \
    WITH_WEBSOCKETS=yes \
    WITH_HTTP_API=no && \
    make -C lib -j$(nproc) \
    CC=clang \
    CXX=clang++ \
    CFLAGS="-O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined -fno-sanitize-recover=all -fPIC" \
    CXXFLAGS="-O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined -fno-sanitize-recover=all -fPIC" \
    LDFLAGS="-fsanitize=address,undefined" \
    WITH_FUZZING=yes \
    WITH_TLS=yes \
    WITH_WEBSOCKETS=yes \
    WITH_HTTP_API=no

# Build reproducer binary for triage
RUN cd /work/mosquitto && \
    clang \
    -O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined -fno-sanitize-recover=all \
    -I/work/mosquitto \
    -I/work/mosquitto/lib \
    -I/work/mosquitto/include \
    -I/work/mosquitto/libcommon \
    -DREPRO_BUILD \
    /work/mosquitto/repro.c \
    /work/mosquitto/harness_packet_read.c \
    -Wl,--whole-archive \
    /work/mosquitto/lib/libmosquitto.a \
    /work/mosquitto/libcommon/libmosquitto_common.a \
    -Wl,--no-whole-archive \
    -lssl -lcrypto -lcjson -lpthread \
    -o /work/repro

# ============================================================================ #
#              COVERAGE BUILD (LLVM source-based coverage)                     #
# ============================================================================ #

# Rebuild mosquitto with coverage instrumentation
RUN cd mosquitto && \
    make -C libcommon clean && make -C lib clean && make -C src clean && \
    make -C libcommon -j$(nproc) \
    CC=clang \
    CXX=clang++ \
    CFLAGS="-O1 -g -fprofile-instr-generate -fcoverage-mapping -fPIC" \
    CXXFLAGS="-O1 -g -fprofile-instr-generate -fcoverage-mapping -fPIC" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping" \
    WITH_FUZZING=yes \
    WITH_TLS=yes \
    WITH_WEBSOCKETS=yes \
    WITH_HTTP_API=no && \
    make -C lib -j$(nproc) \
    CC=clang \
    CXX=clang++ \
    CFLAGS="-O1 -g -fprofile-instr-generate -fcoverage-mapping -fPIC" \
    CXXFLAGS="-O1 -g -fprofile-instr-generate -fcoverage-mapping -fPIC" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping" \
    WITH_FUZZING=yes \
    WITH_TLS=yes \
    WITH_WEBSOCKETS=yes \
    WITH_HTTP_API=no && \
    make -C src -j$(nproc) \
    CC=clang \
    CXX=clang++ \
    CFLAGS="-O1 -g -fprofile-instr-generate -fcoverage-mapping -fPIC" \
    CXXFLAGS="-O1 -g -fprofile-instr-generate -fcoverage-mapping -fPIC" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping" \
    WITH_FUZZING=yes \
    WITH_TLS=yes \
    WITH_WEBSOCKETS=yes \
    WITH_HTTP_API=no

# Build coverage-instrumented fuzzers (non-AFL, just coverage)
RUN cd /work/mosquitto && \
    clang \
    -O1 -g -fprofile-instr-generate -fcoverage-mapping \
    -DWITH_BROKER -DWITH_TLS -DWITH_TLS_PSK -DWITH_PERSISTENCE -DWITH_MEMORY_TRACKING \
    -DWITH_BRIDGE -DWITH_EPOLL -DWITH_SYS_TREE -DWITH_CONTROL \
    -DWITH_UNIX_SOCKETS -DWITH_WEBSOCKETS=WS_IS_BUILTIN \
    -I/work/mosquitto \
    -I/work/mosquitto/src \
    -I/work/mosquitto/lib \
    -I/work/mosquitto/include \
    -I/work/mosquitto/common \
    -I/work/mosquitto/deps \
    -I/work/mosquitto/libcommon \
    /work/mosquitto/harness_broker_connect.c \
    /work/mosquitto/src/mosquitto_broker.a \
    -Wl,--whole-archive /work/mosquitto/libcommon/libmosquitto_common.a -Wl,--no-whole-archive \
    -lssl -lcrypto -lcjson -lpthread -lm -ldl \
    -o /work/cov_broker_connect && \
    clang \
    -O1 -g -fprofile-instr-generate -fcoverage-mapping \
    -DWITH_BROKER -DWITH_TLS -DWITH_TLS_PSK -DWITH_PERSISTENCE -DWITH_MEMORY_TRACKING \
    -DWITH_BRIDGE -DWITH_EPOLL -DWITH_SYS_TREE -DWITH_CONTROL \
    -DWITH_UNIX_SOCKETS -DWITH_WEBSOCKETS=WS_IS_BUILTIN \
    -I/work/mosquitto \
    -I/work/mosquitto/src \
    -I/work/mosquitto/lib \
    -I/work/mosquitto/include \
    -I/work/mosquitto/common \
    -I/work/mosquitto/deps \
    -I/work/mosquitto/libcommon \
    /work/mosquitto/harness_broker_publish.c \
    /work/mosquitto/src/mosquitto_broker.a \
    -Wl,--whole-archive /work/mosquitto/libcommon/libmosquitto_common.a -Wl,--no-whole-archive \
    -lssl -lcrypto -lcjson -lpthread -lm -ldl \
    -o /work/cov_broker_publish && \
    clang \
    -O1 -g -fprofile-instr-generate -fcoverage-mapping \
    -DWITH_BROKER -DWITH_TLS -DWITH_TLS_PSK -DWITH_PERSISTENCE -DWITH_MEMORY_TRACKING \
    -DWITH_BRIDGE -DWITH_EPOLL -DWITH_SYS_TREE -DWITH_CONTROL \
    -DWITH_UNIX_SOCKETS -DWITH_WEBSOCKETS=WS_IS_BUILTIN \
    -I/work/mosquitto \
    -I/work/mosquitto/src \
    -I/work/mosquitto/lib \
    -I/work/mosquitto/include \
    -I/work/mosquitto/common \
    -I/work/mosquitto/deps \
    -I/work/mosquitto/libcommon \
    /work/mosquitto/harness_broker_subscribe.c \
    /work/mosquitto/src/mosquitto_broker.a \
    -Wl,--whole-archive /work/mosquitto/libcommon/libmosquitto_common.a -Wl,--no-whole-archive \
    -lssl -lcrypto -lcjson -lpthread -lm -ldl \
    -o /work/cov_broker_subscribe && \
    clang \
    -O1 -g -fprofile-instr-generate -fcoverage-mapping \
    -I/work/mosquitto \
    -I/work/mosquitto/lib \
    -I/work/mosquitto/include \
    -I/work/mosquitto/libcommon \
    /work/mosquitto/harness_property_parse.c \
    -Wl,--whole-archive \
    /work/mosquitto/lib/libmosquitto.a \
    /work/mosquitto/libcommon/libmosquitto_common.a \
    -Wl,--no-whole-archive \
    -lssl -lcrypto -lcjson -lpthread \
    -o /work/cov_property_parse

# ============================================================================ #
#                           RUNTIME IMAGE                                      #
# ============================================================================ #

FROM docker.io/aflplusplus/aflplusplus:stable

RUN apt-get update && \
    apt-get install -y --no-install-recommends jq xxd libcjson1 && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

WORKDIR /work

RUN mkdir -p seeds output

# Copy all fuzzers and mutators
COPY --from=builder /work/fuzz_packet_read .
COPY --from=builder /work/fuzz_broker_connect .
COPY --from=builder /work/fuzz_broker_publish .
COPY --from=builder /work/fuzz_broker_subscribe .
COPY --from=builder /work/fuzz_property_parse .
COPY --from=builder /work/repro .

COPY --from=builder /work/mutator_connect.so .
COPY --from=builder /work/mutator_property.so .
COPY --from=builder /work/mutator_publish.so .
COPY --from=builder /work/mutator_subscribe.so .

# Coverage binaries
COPY --from=builder /work/cov_broker_connect .
COPY --from=builder /work/cov_broker_publish .
COPY --from=builder /work/cov_broker_subscribe .
COPY --from=builder /work/cov_property_parse .

# Copy corpus (dictionaries and seeds) - context is mqtt/ directory
COPY corpus/ ./corpus/

# Copy entrypoint
COPY fuzz/mosquitto/entrypoint.sh ./entrypoint.sh
RUN chmod +x ./entrypoint.sh

ENV MODULE_ID="mqtt-mosquitto-fuzz"
ENV FUZZER_BIN="./fuzz_packet_read"
ENV REPRO_BIN="./repro"

ENTRYPOINT ["/work/entrypoint.sh"]
