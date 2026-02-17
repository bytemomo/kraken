#!/bin/bash
#
# Extract MQTT packets from PCAP and organize into corpus directories
#
# Usage: ./extract-seeds.sh <pcap_file> <corpus_dir>
#
# Example:
#   ./extract-seeds.sh ./captures/mqtt.pcap ../../../corpus

set -e

if [ $# -lt 2 ]; then
    echo "Usage: $0 <pcap_file> <corpus_dir>"
    exit 1
fi

PCAP="$1"
CORPUS="$2"

if [ ! -f "$PCAP" ]; then
    echo "Error: PCAP file not found: $PCAP"
    exit 1
fi

TMPDIR=$(mktemp -d)
trap "rm -rf $TMPDIR" EXIT

echo "Extracting MQTT packets from $PCAP..."

# Extract all unique MQTT packets
tshark -r "$PCAP" -Y "mqtt" -T fields -e tcp.payload 2>/dev/null | \
    sort -u | \
    while read hex; do
        [ -z "$hex" ] && continue
        # Get first byte (packet type)
        ptype=$(echo "$hex" | cut -c1-2)
        # Create unique filename
        hash=$(echo "$hex" | md5sum | cut -c1-8)
        echo "$hex" | xxd -r -p > "$TMPDIR/${ptype}_${hash}.raw"
    done

echo "Extracted $(ls -1 $TMPDIR | wc -l) unique packets"
echo ""
echo "By packet type:"
ls "$TMPDIR" | cut -d'_' -f1 | sort | uniq -c | sort -rn | while read count ptype; do
    case $ptype in
        10) name="CONNECT" ;;
        20) name="CONNACK" ;;
        30|31|32|33|34|35|36|37|38|39|3a|3b|3c|3d|3e|3f) name="PUBLISH" ;;
        40) name="PUBACK" ;;
        50) name="PUBREC" ;;
        62) name="PUBREL" ;;
        70) name="PUBCOMP" ;;
        82) name="SUBSCRIBE" ;;
        90) name="SUBACK" ;;
        a2) name="UNSUBSCRIBE" ;;
        b0) name="UNSUBACK" ;;
        c0) name="PINGREQ" ;;
        d0) name="PINGRESP" ;;
        e0) name="DISCONNECT" ;;
        f0) name="AUTH" ;;
        *) name="UNKNOWN" ;;
    esac
    printf "  %4d  %s (%s)\n" "$count" "$ptype" "$name"
done

echo ""
echo "Copying to corpus directories..."

# Create directories if needed
mkdir -p "$CORPUS"/{connect,publish,subscribe,unsubscribe,disconnect,pingreq,auth}
mkdir -p "$CORPUS"/{publish-ack,publish-received,publish-release,publish-complete}

# CONNECT (0x10) and CONNACK (0x20)
cp $TMPDIR/10_*.raw "$CORPUS/connect/" 2>/dev/null || true
cp $TMPDIR/20_*.raw "$CORPUS/connect/" 2>/dev/null || true

# PUBLISH variants (0x30-0x3f)
cp $TMPDIR/3?_*.raw "$CORPUS/publish/" 2>/dev/null || true

# PUBACK (0x40)
cp $TMPDIR/40_*.raw "$CORPUS/publish-ack/" 2>/dev/null || true

# PUBREC (0x50)
cp $TMPDIR/50_*.raw "$CORPUS/publish-received/" 2>/dev/null || true

# PUBREL (0x62)
cp $TMPDIR/62_*.raw "$CORPUS/publish-release/" 2>/dev/null || true

# PUBCOMP (0x70)
cp $TMPDIR/70_*.raw "$CORPUS/publish-complete/" 2>/dev/null || true

# SUBSCRIBE (0x82) and SUBACK (0x90)
cp $TMPDIR/82_*.raw "$CORPUS/subscribe/" 2>/dev/null || true
cp $TMPDIR/90_*.raw "$CORPUS/subscribe/" 2>/dev/null || true

# UNSUBSCRIBE (0xa2) and UNSUBACK (0xb0)
cp $TMPDIR/a2_*.raw "$CORPUS/unsubscribe/" 2>/dev/null || true
cp $TMPDIR/b0_*.raw "$CORPUS/unsubscribe/" 2>/dev/null || true

# PINGREQ (0xc0) and PINGRESP (0xd0)
cp $TMPDIR/c0_*.raw "$CORPUS/pingreq/" 2>/dev/null || true
cp $TMPDIR/d0_*.raw "$CORPUS/pingreq/" 2>/dev/null || true

# DISCONNECT (0xe0)
cp $TMPDIR/e0_*.raw "$CORPUS/disconnect/" 2>/dev/null || true

# AUTH (0xf0) - MQTT 5.0
cp $TMPDIR/f0_*.raw "$CORPUS/auth/" 2>/dev/null || true

# Unknown/malformed packets go to publish for fuzzing
for f in $TMPDIR/*.raw; do
    ptype=$(basename "$f" | cut -c1-2)
    case $ptype in
        10|20|3?|40|50|62|70|82|90|a2|b0|c0|d0|e0|f0) ;;
        *) cp "$f" "$CORPUS/publish/" 2>/dev/null || true ;;
    esac
done

echo ""
echo "Corpus sizes:"
for d in "$CORPUS"/*/; do
    count=$(ls -1 "$d" 2>/dev/null | wc -l)
    printf "  %-20s %d files\n" "$(basename $d):" "$count"
done

echo ""
echo "Done."
