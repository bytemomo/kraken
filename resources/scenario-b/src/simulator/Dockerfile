# KickCAT Simulator

FROM debian:bookworm-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    git \
    python3 \
    python3-pip \
    python3-venv \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install --break-system-packages conan

WORKDIR /build
RUN git clone https://github.com/Siviuze/KickCAT.git && \
    cd KickCAT && \
    git checkout v2.4-rc0

WORKDIR /build/KickCAT

# Copy patched source files
COPY network_simulator.cc simulation/network_simulator.cc
COPY AbstractSPI.h lib/slave/include/kickcat/AbstractSPI.h

# Setup build with conan
RUN conan profile detect --force && \
    ./setup_build.sh build

# Build simulator
WORKDIR /build/KickCAT/build
RUN cmake .. \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_TOOLCHAIN_FILE=toolchain.cmake \
    -DBUILD_SIMULATION=ON \
    -DBUILD_EXAMPLES=OFF \
    -DBUILD_UNIT_TESTS=OFF \
    -DBUILD_TOOLS=OFF && \
    make -j$(nproc) network_simulator

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 \
    libstdc++6 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/KickCAT/build/simulation/network_simulator /usr/local/bin/simulator
COPY foot.bin /eeprom/
COPY foot.xml /app/

WORKDIR /app
CMD ["simulator"]
