set -e

CERTS_DIR="/certs"
DAYS_VALID=365
KEY_SIZE=2048

# Check if certificates already exist
if [ -f "$CERTS_DIR/ca.crt" ] && [ -f "$CERTS_DIR/server.crt" ]; then
    echo "Certificates already exist. Skipping generation."
    exit 0
fi

echo "=== Generating certificates for Scenario A ==="

# Install OpenSSL if not present
apk add --no-cache openssl > /dev/null 2>&1 || true

cd "$CERTS_DIR"

# Generate CA Certificate
echo "Generating CA certificate..."

cat > ca.cnf << EOF
[req]
default_bits = $KEY_SIZE
prompt = no
default_md = sha256
distinguished_name = dn
x509_extensions = v3_ca

[dn]
C = IT
ST = Tuscany
L = Pisa
O = Nautilus Lab
OU = ICS Security Research
CN = Scenario A Root CA

[v3_ca]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true
keyUsage = critical, digitalSignature, cRLSign, keyCertSign
EOF

openssl genrsa -out ca.key $KEY_SIZE
openssl req -x509 -new -nodes -key ca.key -sha256 -days $DAYS_VALID \
    -out ca.crt -config ca.cnf

# Generate Server Certificate (for MQTT broker)
echo "Generating server certificate..."

cat > server.cnf << EOF
[req]
default_bits = $KEY_SIZE
prompt = no
default_md = sha256
distinguished_name = dn
req_extensions = req_ext

[dn]
C = IT
ST = Tuscany
L = Pisa
O = Nautilus Lab
OU = MQTT Broker
CN = mqtt-broker

[req_ext]
subjectAltName = @alt_names

[alt_names]
DNS.1 = mqtt-broker
DNS.2 = localhost
DNS.3 = broker
DNS.4 = scenario-a-broker
IP.1 = 127.0.0.1
IP.2 = 172.20.0.10
IP.3 = 172.21.0.10
EOF

cat > server_ext.cnf << EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = mqtt-broker
DNS.2 = localhost
DNS.3 = broker
DNS.4 = scenario-a-broker
IP.1 = 127.0.0.1
IP.2 = 172.20.0.10
IP.3 = 172.21.0.10
EOF

openssl genrsa -out server.key $KEY_SIZE
openssl req -new -key server.key -out server.csr -config server.cnf
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out server.crt -days $DAYS_VALID -sha256 -extfile server_ext.cnf

# Generate Client Certificates
generate_client_cert() {
    local name=$1
    local cn=$2

    echo "Generating client certificate for $name..."

    cat > "${name}.cnf" << EOF
[req]
default_bits = $KEY_SIZE
prompt = no
default_md = sha256
distinguished_name = dn

[dn]
C = IT
ST = Tuscany
L = Pisa
O = Nautilus Lab
OU = Field Device
CN = $cn
EOF

    cat > "${name}_ext.cnf" << EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
EOF

    openssl genrsa -out "${name}.key" $KEY_SIZE
    openssl req -new -key "${name}.key" -out "${name}.csr" -config "${name}.cnf"
    openssl x509 -req -in "${name}.csr" -CA ca.crt -CAkey ca.key -CAcreateserial \
        -out "${name}.crt" -days $DAYS_VALID -sha256 -extfile "${name}_ext.cnf"

    rm -f "${name}.csr" "${name}.cnf" "${name}_ext.cnf"
}

generate_client_cert "plc-01" "plc-01"
generate_client_cert "rtu-01" "rtu-01"
generate_client_cert "scada-01" "scada-01"
generate_client_cert "kraken" "kraken-scanner"

# Clean up temporary files
rm -f ca.cnf server.cnf server_ext.cnf server.csr ca.srl

# Set proper permissions
chmod 644 *.crt
chmod 600 *.key

echo "=== Certificate generation complete ==="
echo "Generated files:"
ls -la "$CERTS_DIR"
