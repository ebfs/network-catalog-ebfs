# Network Catalog

Network Catalog is a lightweight Python-based network observability and inventory platform.

It combines:

- active network discovery
- service enumeration
- passive traffic telemetry
- historical persistence
- privacy-aware storage

into a single modular project.

The goal is to provide visibility into:
- what devices exist on a network
- what services they expose
- how they communicate over time

without storing raw packet payloads or intrusive endpoint data.

---

# Features

## Active Discovery (`scanner.py`)

Performs active network reconnaissance using Nmap.

Capabilities:
- host discovery
- MAC address collection
- hostname detection
- vendor identification
- open port detection
- service fingerprinting
- basic operating system detection

The scanner:
1. detects live hosts on the selected subnet
2. performs deeper service enumeration on discovered devices
3. stores results in a persistent SQLite database

### Discovery Phase

Uses:

```text
-sn -PR
```

to:
- identify live devices
- perform ARP discovery
- avoid unnecessary port scanning initially

### Deep Scan Phase

Uses:

```text
-F -sV -T4
```

to:
- perform fast TCP port scanning
- identify running services
- fingerprint products and versions
- catalog exposed network services

Examples:
- HTTP
- HTTPS
- DNS
- SIP
- RTSP
- SSH

Cataloged data includes:
- IP address (hashed before storage)
- MAC address (hashed before storage)
- hostname
- hardware vendor
- detected operating system
- open ports
- detected services/products

---

## Passive Traffic Telemetry (`traffic.py`)

Passively monitors network traffic using Scapy and Npcap.

The monitor:
- captures IP traffic
- classifies communication direction
- aggregates packets into flows
- stores summarized network conversations

Unlike packet sniffers that retain payloads, this project stores:
- metadata only
- not packet contents

This significantly reduces:
- storage usage
- privacy concerns
- processing overhead

### Captured Flow Metadata

Each flow includes:
- source IP
- destination IP
- source port
- destination port
- protocol
- packet count
- byte count
- first seen timestamp
- last seen timestamp

### Direction Classification

Traffic is categorized as:
- INCOMING
- OUTGOING
- INTERNAL
- EXTERNAL

### Service Identification

Traffic monitor attempts to resolve common services:
- HTTPS
- DNS
- HTTP
- SSH
- RTSP
- etc.

using standard port mappings.

### Flow Aggregation

Rather than storing every packet individually, packets are aggregated into flows using:
- source/destination addresses
- ports
- protocol

Flows are persisted after inactivity timeout expiration.

This approach is conceptually similar to:
- NetFlow
- IPFIX
- lightweight NDR telemetry

---

# Database (`SQLite`)

The project uses SQLite for persistence.

Reasons for using SQLite:
- zero configuration
- no external database server required
- portable single-file storage
- lightweight
- ideal for local telemetry projects
- easy querying and inspection

The database file:

```text
network_catalog.db
```

stores:
- device inventory
- discovered services
- historical traffic flows

SQLite is appropriate because:
- telemetry volume is currently moderate
- setup simplicity is important
- portability matters
- local analysis is the primary use case

---

# Privacy Design

Sensitive identifiers are obfuscated before persistence.

Examples:
- IP addresses
- MAC addresses

are hashed using the project's obfuscation layer before being stored in the database.

This allows:
- historical correlation
- uniqueness tracking

without directly exposing raw endpoint identifiers.

---

# Project Structure

```text
database.py
    SQLAlchemy engine/session setup

models.py
    ORM models for:
    - devices
    - services
    - flows

scanner.py
    Active network discovery and service enumeration

traffic.py
    Passive traffic telemetry and flow collection

obfuscation.py
    Identifier hashing/privacy utilities
```

---

# Python Dependencies

Install required Python packages:

```bash
pip install python-nmap scapy sqlalchemy
```

---

# External Dependencies

## Nmap

Required for:
- active scanning
- service detection
- OS fingerprinting

Install:
https://nmap.org/download.html

---

## Npcap (Windows)

Required for:
- packet capture
- passive monitoring with Scapy

Install:
https://npcap.com

Recommended install options:
- WinPcap compatibility mode
- loopback support enabled

---

# Running

## Active Scan

```bash
python scanner.py
```

## Passive Monitoring

```bash
python traffic.py
```

---

# Current Capabilities

- Active network inventory
- Service discovery
- Passive traffic monitoring
- Historical flow persistence
- Protocol identification
- Direction classification
- Privacy-aware storage
- Lightweight telemetry collection

---

# Future Improvements

Planned or possible future enhancements:
- bidirectional flow normalization
- DNS hostname enrichment
- dashboard/web UI
- top talker analytics
- subnet classification
- device-flow correlation
- alerting
- live statistics
- REST API
- flow indexing optimization
