# Security Configuration Profiles

This directory contains three security configuration profiles for testing
Kraken's detection capabilities. Each profile represents a different
security posture with varying levels of vulnerabilities.

## Profile Overview

| Profile  | Security Level | Expected Kraken Findings    |
| -------- | -------------- | --------------------------- |
| insecure | None           | All checks fail (default)   |
| partial  | Medium         | Some checks pass, some fail |
| hardened | High           | No findings (clean scan)    |

## Directory Structure

```
profiles/
├── common/             # Shared configuration files
│   ├── passwd          # User credentials (hashed at runtime)
│   ├── bridge.conf     # MQTT bridge configuration
│   └── test-credentials.txt
├── insecure/           # Maximum vulnerability profile
│   ├── mosquitto.conf
│   ├── acl.conf
├── partial/            # Partial security profile
│   ├── mosquitto.conf
│   └── acl.conf
└── hardened/           # Full security profile
    ├── mosquitto.conf
    └── acl.conf
```

## Usage

Profiles are selected via the `SECURITY_PROFILE` environment variable.
Docker Compose mounts the appropriate configuration files directly.

```bash
# Use insecure profile (default)
docker compose up -d

# Use partial security profile
SECURITY_PROFILE=partial docker compose up -d

# Use hardened profile
SECURITY_PROFILE=hardened docker compose up -d

# Switch profile on running environment
SECURITY_PROFILE=hardened docker compose up -d --force-recreate broker
```

## Profile Details

### Insecure Profile

**Purpose**: Maximum vulnerability exposure for comprehensive testing

**Vulnerabilities Present**:

- MQTT-ANON: Anonymous access on all ports
- MQTT-PUBSUB-ANON: No authentication for publish/subscribe
- MQTT-ACL-\*: No ACL enforcement
- mqtt-sys-disclosure: $SYS topics accessible to everyone
- TLS-SUPPORT-OVERVIEW: Weak TLS (old versions allowed)
- No client certificate verification

**Ports**:

- 1883: Plaintext, anonymous
- 8883: TLS, anonymous (weak TLS)
- 8884: mTLS port but certificates not required

### Partial Security Profile

**Purpose**: Realistic "legacy" configuration with some security measures

**Security Measures**:

- Password authentication on TLS ports
- TLS 1.2 on secure ports
- ACL file enabled
- mTLS available on port 8884

**Remaining Vulnerabilities**:

- Anonymous access on port 1883 ("for legacy devices")
- Weak ACLs (users can access more than needed)
- $SYS topics accessible to authenticated users
- No TLS 1.3

### Hardened Profile

**Purpose**: Best-practice configuration, should produce zero findings

**Security Measures**:

- No plaintext listener (port 1883 disabled)
- TLS 1.3 enforced
- mTLS required on primary port
- Strict ACLs with least-privilege
- $SYS topics restricted to admin only
- sys_interval=0 (disables $SYS updates)
- Connection limits for DoS protection
