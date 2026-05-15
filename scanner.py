import nmap
import threading
import time
import ipaddress

from datetime import datetime, UTC

from scapy.all import get_if_addr
from scapy.all import conf

from database import Base
from database import engine
from database import SessionLocal

from models import Device
from models import Service

from obfuscation import hash_value


scan_complete = False

current_host = "None"

current_host_start = None


def format_time(seconds_float):

    seconds = int(seconds_float)

    milliseconds = int(
        (seconds_float - seconds) * 1000
    )

    return f"{seconds}s {milliseconds}ms"


def scan_progress_timer():

    while not scan_complete:

        if current_host_start:

            host_elapsed = (
                time.time() - current_host_start
            )

            print(
                f"[INFO] Scanning {current_host} | "
                f"Elapsed: {format_time(host_elapsed)}"
            )

        time.sleep(5)


#
# Database Setup
#

Base.metadata.create_all(bind=engine)

db = SessionLocal()

scanner = nmap.PortScanner()


#
# Local Network Detection
#

LOCAL_IP = get_if_addr(conf.iface)

DEFAULT_NETWORK = str(

    ipaddress.ip_network(
        f"{LOCAL_IP}/24",
        strict=False
    )

)


#
# User-configurable Network
#

network = input(
    f"Enter network to scan "
    f"(default: {DEFAULT_NETWORK}): "
).strip()

if not network:

    network = DEFAULT_NETWORK


print(f"\nScanning {network}...")


#
# Total Scan Timer
#

total_scan_start = time.time()


#
# Start Progress Thread
#

progress_thread = threading.Thread(
    target=scan_progress_timer,
    daemon=True
)

progress_thread.start()


#
# Fast Discovery Phase
#

discovery_start = time.time()

scanner.scan(
    hosts=network,
    arguments="-sn -PR"
)

discovery_elapsed = (
    time.time() - discovery_start
)

print(
    f"\nDiscovery completed in "
    f"{format_time(discovery_elapsed)}"
)

live_hosts = scanner.all_hosts()

print(f"Discovered {len(live_hosts)} live hosts")


#
# Store Scan Results
#

scan_results = {}


#
# Deep Scan Phase
#

for host in live_hosts:

    current_host = host

    current_host_start = time.time()

    print(f"\nDeep scanning {host}...")

    scanner.scan(
        hosts=host,
        arguments="-F -sV -T4"
    )

    if host in scanner.all_hosts():

        scan_results[host] = scanner[host]

    host_elapsed = (
        time.time() - current_host_start
    )

    print(
        f"Finished {host} "
        f"in {format_time(host_elapsed)}"
    )


#
# Stop Progress Thread
#

scan_complete = True

hosts = live_hosts

print(f"\nFound {len(hosts)} hosts")


#
# Process Hosts
#

for host in hosts:

    print("=" * 60)

    print(f"Host: {host}")

    host_data = scan_results.get(host)

    hashed_ip = hash_value(host)

    # Fallback for hosts with no deep scan data
    if not host_data:

        print("No detailed scan data available.")

        current_time = datetime.now(UTC)

        device = db.query(Device).filter(
            Device.ip == hashed_ip
        ).first()

        if not device:

            device = Device(ip=hashed_ip)

            db.add(device)

            print(f"Added: {host}")

        else:

            print(f"Updated: {host}")

        device.last_seen = current_time

        continue


    hostname = host_data.hostname()

    print(f"Hostname: {hostname}")

    addresses = host_data.get(
        "addresses",
        {}
    )

    mac = addresses.get("mac")

    print(f"MAC: {mac}")

    hashed_mac = hash_value(mac)

    vendor_info = host_data.get(
        "vendor",
        {}
    )

    vendor = vendor_info.get(mac)

    print(f"Vendor: {vendor}")


    #
    # OS Detection
    #

    os_name = None

    if "osmatch" in host_data:

        os_matches = host_data["osmatch"]

        if os_matches:

            best_match = os_matches[0]

            os_name = best_match["name"]

            print(f"OS: {os_name}")


    current_time = datetime.now(UTC)

    device = db.query(Device).filter(
        Device.ip == hashed_ip
    ).first()

    if not device:

        device = Device(
            ip=hashed_ip,
            mac=hashed_mac
        )

        db.add(device)

        print(f"Added: {host}")

    else:

        print(f"Updated: {host}")


    device.hostname = hostname
    device.ip = hashed_ip
    device.mac = hashed_mac
    device.vendor = vendor
    device.os = os_name
    device.last_seen = current_time


    #
    # Service Detection
    #

    if "tcp" in host_data:

        print("\nOpen Ports:")

        # Remove previous services
        device.services.clear()

        for port in host_data["tcp"]:

            service = host_data["tcp"][port]

            service_name = service.get("name")

            product = service.get("product")

            version = service.get("version")

            print(f"  Port: {port}")

            print(f"  Service: {service_name}")

            if product:

                print(f"  Product: {product}")

            if version:

                print(f"  Version: {version}")

            print("-" * 20)

            service_record = Service(
                port=port,
                protocol="tcp",
                service_name=service_name,
                product=product,
                version=version
            )

            device.services.append(service_record)


#
# Commit Database Changes
#

db.commit()

total_elapsed = (
    time.time() - total_scan_start
)

print(
    f"\nDone. Total scan time: "
    f"{format_time(total_elapsed)}"
)
