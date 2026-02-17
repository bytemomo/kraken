FROM alpine:edge

RUN apk add --no-cache \
    gstreamer \
    gst-plugins-base \
    gst-plugins-good \
    gst-plugins-bad \
    gst-plugins-ugly \
    gst-rtsp-server \
    ffmpeg \
    openssl \
    bash \
    python3 \
    py3-pip \
    py3-gobject3 \
    py3-gst \
    glib

WORKDIR /app

COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENV RTSP_PORT=554 \
    RTSP_PATH=/stream \
    RTSP_AUTH=none \
    RTSP_USER=admin \
    RTSP_PASS=admin \
    RTSP_TLS=false \
    CAMERA_ID=camera-1 \
    VIDEO_PATTERN=smpte

EXPOSE 554

ENTRYPOINT ["/app/entrypoint.sh"]
