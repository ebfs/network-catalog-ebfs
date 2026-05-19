import time
import socket
import ipaddress

from datetime import datetime, UTC

from scapy.all import sniff
from scapy.all import AsyncSniffer
from scapy.all import get_if_addr
from scapy.all import conf

from scapy.layers.inet import IP
from scapy.layers.inet import TCP
from scapy.layers.inet import UDP

from ipwhois import IPWhois

from models import Flow

from database import Base
from database import engine
from database import SessionLocal

from obfuscation import hash_value


#
# Database Setup
#

Base.metadata.create_all(bind=engine)

db = SessionLocal()


#
# Flow Cache
#

flows = {}

FLOW_TIMEOUT = 60


#
# Local Network Detection
#

LOCAL_IP = get_if_addr(conf.iface)

LOCAL_NETWORK = ipaddress.ip_network(
    f"{LOCAL_IP}/24",
    strict=False
)


#
# Direction Classification
#

def classify_direction(src_ip, dst_ip):

    try:

        src_local = (
            ipaddress.ip_address(src_ip)
            in LOCAL_NETWORK
        )

        dst_local = (
            ipaddress.ip_address(dst_ip)
            in LOCAL_NETWORK
        )

        if src_local and not dst_local:

            return "OUTGOING"

        if not src_local and dst_local:

            return "INCOMING"

        if src_local and dst_local:

            return "INTERNAL"

        return "EXTERNAL"

    except Exception:

        return "UNKNOWN"


#
# IP Helpers
#

def is_internal_ip(ip):

    try:

        return (
            ipaddress.ip_address(ip)
            in LOCAL_NETWORK
        )

    except Exception:

        return False


def normalize_ip(ip):

    #
    # Internal IPs are hashed
    # External IPs remain raw for enrichment
    #

    if is_internal_ip(ip):

        return hash_value(ip)

    return ip


#
# Enrichment Helpers
#

def enrich_ip(ip):

    enrichment = {

        "asn": None,

        "org": None,

        "country": None,

        "rdns": None
    }

    #
    # Skip enrichment for internal IPs
    #

    if is_internal_ip(ip):

        return enrichment

    #
    # ASN / Organization / Country Lookup
    #

    try:

        result = IPWhois(ip).lookup_rdap()

        enrichment["asn"] = (
            result.get("asn")
        )

        enrichment["org"] = (
            result.get("network", {})
            .get("name")
        )

        enrichment["country"] = (
            result.get("network", {})
            .get("country")
        )

    except Exception:

        pass

    #
    # Reverse DNS
    #

    try:

        rdns = socket.gethostbyaddr(ip)[0]

        enrichment["rdns"] = rdns

    except Exception:

        pass

    return enrichment


#
# Helpers
#

def get_protocol(packet):

    if packet.haslayer(TCP):

        return "TCP"

    if packet.haslayer(UDP):

        return "UDP"

    return "OTHER"


def get_ports(packet):

    src_port = None
    dst_port = None

    if packet.haslayer(TCP):

        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport

    elif packet.haslayer(UDP):

        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport

    return src_port, dst_port


def get_service_name(port, protocol):

    if not port:

        return "UNKNOWN"

    try:

        return socket.getservbyport(
            port,
            protocol.lower()
        ).upper()

    except Exception:

        return "UNKNOWN"


def flush_expired_flows():

    current_time = time.time()

    expired_keys = []

    for key, flow in flows.items():

        last_seen_unix = flow["last_seen_unix"]

        if (
            current_time - last_seen_unix
            > FLOW_TIMEOUT
        ):

            save_flow(flow)

            expired_keys.append(key)

    for key in expired_keys:

        del flows[key]


def save_flow(flow):

    record = Flow(

        #
        # Core Flow Metadata
        #

        src_ip=flow["src_ip"],

        dst_ip=flow["dst_ip"],

        src_port=flow["src_port"],

        dst_port=flow["dst_port"],

        protocol=flow["protocol"],

        packet_count=flow["packet_count"],

        byte_count=flow["byte_count"],

        first_seen=flow["first_seen"],

        last_seen=flow["last_seen"],

        #
        # Internal / External Classification
        #

        src_is_internal=flow["src_is_internal"],

        dst_is_internal=flow["dst_is_internal"],

        #
        # Source Enrichment
        #

        src_asn=flow["src_asn"],

        src_org=flow["src_org"],

        src_country=flow["src_country"],

        src_rdns=flow["src_rdns"],

        #
        # Destination Enrichment
        #

        dst_asn=flow["dst_asn"],

        dst_org=flow["dst_org"],

        dst_country=flow["dst_country"],

        dst_rdns=flow["dst_rdns"]
    )

    db.add(record)

    db.commit()

    print(
        f"[FLOW SAVED] "
        f"{flow['src_ip']}:{flow['src_port']} "
        f"-> "
        f"{flow['dst_ip']}:{flow['dst_port']} "
        f"{flow['protocol']} "
        f"Packets={flow['packet_count']} "
        f"Bytes={flow['byte_count']}"
    )


#
# Packet Processing
#

def process_packet(packet):

    if not packet.haslayer(IP):

        return

    src_ip_raw = packet[IP].src
    dst_ip_raw = packet[IP].dst

    direction = classify_direction(
        src_ip_raw,
        dst_ip_raw
    )

    #
    # Internal / External Classification
    #

    src_is_internal = is_internal_ip(
        src_ip_raw
    )

    dst_is_internal = is_internal_ip(
        dst_ip_raw
    )

    #
    # IP Normalization
    #

    src_ip = normalize_ip(src_ip_raw)

    dst_ip = normalize_ip(dst_ip_raw)

    #
    # Enrichment
    #

    src_enrichment = enrich_ip(
        src_ip_raw
    )

    dst_enrichment = enrich_ip(
        dst_ip_raw
    )

    protocol = get_protocol(packet)

    src_port, dst_port = get_ports(packet)

    service_port = None

    if src_port and src_port < 1024:

        service_port = src_port

    elif dst_port and dst_port < 1024:

        service_port = dst_port

    else:

        service_port = dst_port

    service_name = get_service_name(
        service_port,
        protocol
    )

    print(
        f"[{direction}] "
        f"{protocol} "
        f"{src_ip_raw}:{src_port} "
        f"-> "
        f"{dst_ip_raw}:{dst_port} "
        f"[{service_name}]"
    )

    packet_size = len(packet)

    now = datetime.now(UTC)

    now_unix = time.time()

    flow_key = (

        src_ip,
        dst_ip,
        src_port,
        dst_port,
        protocol
    )

    if flow_key not in flows:

        flows[flow_key] = {

            #
            # Core Flow Metadata
            #

            "src_ip": src_ip,

            "dst_ip": dst_ip,

            "src_port": src_port,

            "dst_port": dst_port,

            "protocol": protocol,

            "packet_count": 0,

            "byte_count": 0,

            "first_seen": now,

            "last_seen": now,

            "last_seen_unix": now_unix,

            #
            # Internal / External Classification
            #

            "src_is_internal": src_is_internal,

            "dst_is_internal": dst_is_internal,

            #
            # Source Enrichment
            #

            "src_asn": src_enrichment["asn"],

            "src_org": src_enrichment["org"],

            "src_country": src_enrichment["country"],

            "src_rdns": src_enrichment["rdns"],

            #
            # Destination Enrichment
            #

            "dst_asn": dst_enrichment["asn"],

            "dst_org": dst_enrichment["org"],

            "dst_country": dst_enrichment["country"],

            "dst_rdns": dst_enrichment["rdns"]
        }

    flow = flows[flow_key]

    flow["packet_count"] += 1

    flow["byte_count"] += packet_size

    flow["last_seen"] = now

    flow["last_seen_unix"] = now_unix

    flush_expired_flows()


#
# Main
#

print("=" * 60)
print("Passive Traffic Monitor")
print("=" * 60)

print(f"Capture Interface: {conf.iface}")
print(f"Local IP: {LOCAL_IP}")
print(f"Monitoring Network: {LOCAL_NETWORK}")

print("\nStarting capture...")
print("Press CTRL+C to stop.\n")

sniffer = None

try:

    sniffer = AsyncSniffer(

        prn=process_packet,

        store=False,

        filter="ip"
    )

    sniffer.start()

    while True:

        time.sleep(1)

except KeyboardInterrupt:

    print("\nStopping monitor...")

    if sniffer:

        sniffer.stop()

    for flow in flows.values():

        save_flow(flow)

    db.close()

    print("Done.")
    