# KickCAT Master (Python)

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    python3-venv \
    build-essential \
    cmake \
    git \
    iproute2 \
    ca-certificates \
    && pip3 install --break-system-packages kickcat \
    && apt-get purge -y build-essential cmake git \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY easycat.py /app/

CMD ["python3", "easycat.py"]
