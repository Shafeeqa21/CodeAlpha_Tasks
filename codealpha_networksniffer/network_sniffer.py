from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, Raw
from datetime import datetime

# Map protocol numbers to readable names
PROTOCOL_MAP = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
}

packet_count = 0


def format_payload(payload_bytes, max_len=80):
    """Try to show payload as readable text, else show hex."""
    try:
        text = payload_bytes.decode("utf-8", errors="replace")
        text = text.replace("\n", " ").replace("\r", " ")
        return text[:max_len] + ("..." if len(text) > max_len else "")
    except Exception:
        return payload_bytes[:max_len].hex()


def process_packet(packet):
    global packet_count
    packet_count += 1
    timestamp = datetime.now().strftime("%H:%M:%S")

    print(f"\n{'=' * 60}")
    print(f"[#{packet_count}] Time: {timestamp}")

    # --- ARP packets (Layer 2, no IP layer) ---
    if packet.haslayer(ARP):
        arp = packet[ARP]
        op = "who-has (request)" if arp.op == 1 else "is-at (reply)"
        print(f"Protocol : ARP ({op})")
        print(f"Src IP   : {arp.psrc}  |  Src MAC: {arp.hwsrc}")
        print(f"Dst IP   : {arp.pdst}  |  Dst MAC: {arp.hwdst}")
        return

    # --- IP-based packets ---
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        proto_num = ip_layer.proto
        proto_name = PROTOCOL_MAP.get(proto_num, f"Other({proto_num})")

        print(f"Protocol : {proto_name}")
        print(f"Src IP   : {src_ip}")
        print(f"Dst IP   : {dst_ip}")
        print(f"TTL      : {ip_layer.ttl}  |  Packet Len: {len(packet)} bytes")

        # TCP details
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            print(f"Src Port : {tcp.sport}  ->  Dst Port: {tcp.dport}")
            flags = tcp.sprintf("%TCP.flags%")
            print(f"Flags    : {flags}")

        # UDP details
        elif packet.haslayer(UDP):
            udp = packet[UDP]
            print(f"Src Port : {udp.sport}  ->  Dst Port: {udp.dport}")

        # ICMP details
        elif packet.haslayer(ICMP):
            icmp = packet[ICMP]
            print(f"ICMP Type: {icmp.type}  Code: {icmp.code}")

        # Payload (application data)
        if packet.haslayer(Raw):
            payload = bytes(packet[Raw].load)
            print(f"Payload  : {format_payload(payload)}")
        else:
            print("Payload  : <none / encrypted / header-only>")
    else:
        print("Protocol : Non-IP packet (skipped detailed parsing)")


def main():
    print("=" * 60)
    print(" Basic Network Sniffer - CodeAlpha Task 1")
    print("=" * 60)
    print("Starting capture... Press Ctrl+C to stop.\n")

    try:
        # count=0 means capture indefinitely until Ctrl+C
        # filter: leave empty to capture all traffic, or use BPF filter e.g. "tcp" or "port 80"
        sniff(prn=process_packet, store=False, count=0)
    except PermissionError:
        print("\n[ERROR] Permission denied. Run this script as root/administrator.")
    except KeyboardInterrupt:
        print(f"\n\nCapture stopped by user. Total packets captured: {packet_count}")


if __name__ == "__main__":
    main()