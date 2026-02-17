#!/bin/bash

set -e

RTSP_PORT="${RTSP_PORT:-554}"
RTSP_PATH="${RTSP_PATH:-/stream}"
RTSP_AUTH="${RTSP_AUTH:-none}"
RTSP_USER="${RTSP_USER:-admin}"
RTSP_PASS="${RTSP_PASS:-admin}"
RTSP_TLS="${RTSP_TLS:-false}"
CAMERA_ID="${CAMERA_ID:-camera-1}"
VIDEO_PATTERN="${VIDEO_PATTERN:-smpte}"

echo "Starting RTSP Camera Simulator"
echo "  Camera ID: ${CAMERA_ID}"
echo "  Port: ${RTSP_PORT}"
echo "  Path: ${RTSP_PATH}"
echo "  Auth: ${RTSP_AUTH}"
echo "  TLS: ${RTSP_TLS}"

cat > /app/rtsp_server.py << 'PYEOF'
#!/usr/bin/env python3
import gi
gi.require_version('Gst', '1.0')
gi.require_version('GstRtspServer', '1.0')
from gi.repository import Gst, GstRtspServer, GLib
import os
import sys
import base64

Gst.init(None)

class RTSPServer:
    def __init__(self):
        self.port = os.environ.get('RTSP_PORT', '554')
        self.path = os.environ.get('RTSP_PATH', '/stream')
        self.auth_mode = os.environ.get('RTSP_AUTH', 'none')
        self.username = os.environ.get('RTSP_USER', 'admin')
        self.password = os.environ.get('RTSP_PASS', 'admin')
        self.camera_id = os.environ.get('CAMERA_ID', 'camera-1')
        self.pattern = os.environ.get('VIDEO_PATTERN', 'smpte')

        self.server = GstRtspServer.RTSPServer()
        self.server.set_service(self.port)

        self.factory = GstRtspServer.RTSPMediaFactory()

        pipeline = (
            f'( videotestsrc pattern={self.pattern} ! '
            f'textoverlay text="{self.camera_id}" valignment=top halignment=left font-desc="Sans 24" ! '
            f'clockoverlay halignment=right valignment=top font-desc="Sans 18" ! '
            f'video/x-raw,width=640,height=480,framerate=25/1 ! '
            f'x264enc tune=zerolatency bitrate=500 speed-preset=superfast ! '
            f'rtph264pay name=pay0 pt=96 )'
        )
        self.factory.set_launch(pipeline)
        self.factory.set_shared(True)

        if self.auth_mode == 'basic':
            self._setup_basic_auth()
        elif self.auth_mode == 'digest':
            self._setup_digest_auth()

        mounts = self.server.get_mount_points()
        mounts.add_factory(self.path, self.factory)

        for alt_path in ['/live.sdp', '/video', '/h264', '/stream1']:
            if alt_path != self.path:
                mounts.add_factory(alt_path, self.factory)

    def _setup_basic_auth(self):
        auth = GstRtspServer.RTSPAuth()
        token = GstRtspServer.RTSPToken()
        token.set_string('media.factory.role', 'user')

        basic = GLib.Bytes.new(f'{self.username}:{self.password}'.encode())
        auth.add_basic(base64.b64encode(basic.get_data()).decode(), token)

        self.server.set_auth(auth)

        permissions = GstRtspServer.RTSPPermissions()
        permissions.add_permission_for_role('user', 'media.factory.access', True)
        permissions.add_permission_for_role('user', 'media.factory.construct', True)
        self.factory.set_permissions(permissions)

    def _setup_digest_auth(self):
        auth = GstRtspServer.RTSPAuth()
        token = GstRtspServer.RTSPToken()
        token.set_string('media.factory.role', 'user')

        auth.add_digest(self.username, self.password, token)
        self.server.set_auth(auth)

        permissions = GstRtspServer.RTSPPermissions()
        permissions.add_permission_for_role('user', 'media.factory.access', True)
        permissions.add_permission_for_role('user', 'media.factory.construct', True)
        self.factory.set_permissions(permissions)

    def run(self):
        self.server.attach(None)
        print(f'RTSP server running at rtsp://0.0.0.0:{self.port}{self.path}')
        print(f'Authentication mode: {self.auth_mode}')
        loop = GLib.MainLoop()
        try:
            loop.run()
        except KeyboardInterrupt:
            pass

if __name__ == '__main__':
    server = RTSPServer()
    server.run()
PYEOF

exec python3 /app/rtsp_server.py
