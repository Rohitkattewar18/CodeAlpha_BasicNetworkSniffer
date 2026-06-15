from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.packet import Raw

def process_packet(packet):
    """
    Callback function that processes each captured packet.
    Extracts the source/destination IP, protocol type, and payload.
    """
    # We only care about IP (Internet Protocol) packets for this basic sniffer
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        
        # Determine the Transport Layer protocol (TCP, UDP, ICMP, etc.)
        protocol = "Other"
        src_port = "-"
        dst_port = "-"
        
        if packet.haslayer(TCP):
            protocol = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif packet.haslayer(UDP):
            protocol = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        elif packet.haslayer(ICMP):
            protocol = "ICMP"
        
        # Display the parsed information
        if protocol in ["TCP", "UDP"]:
            print(f"\n[+] {protocol} Packet: {ip_src}:{src_port} -> {ip_dst}:{dst_port}")
        else:
            print(f"\n[+] {protocol} Packet: {ip_src} -> {ip_dst}")
            
        # If there's raw data (the payload/actual content being sent), let's print a snippet
        if packet.haslayer(Raw):
            try:
                # The payload is usually bytes. We try to decode it to a string.
                # errors='ignore' ensures the script doesn't crash on binary data.
                payload = packet[Raw].load.decode('utf-8', errors='ignore')
                # Print the first 100 characters to keep the console clean
                clean_payload = payload[:100].replace('\r', '').replace('\n', ' ')
                print(f"    Payload: {clean_payload}...") 
            except Exception:
                print(f"    Payload: <Binary Data>")

def main():
    print("=" * 50)
    print("Starting the Python Packet Sniffer...")
    print("Capturing network traffic. Press Ctrl+C to stop.")
    print("=" * 50)
    
    # sniff() is the core scapy function that captures packets from the network interface.
    # prn=process_packet means our custom function will be called for every packet received.
    # store=False ensures we don't save every packet in RAM.
    try:
        sniff(prn=process_packet, store=False)
    except PermissionError:
        print("\n[!] Error: You need administrative privileges to capture packets.")
        print("Please run your terminal or command prompt as Administrator.")
    except Exception as e:
        print(f"\n[!] An error occurred: {e}")
        print("-> Make sure you have Npcap installed on Windows (https://npcap.com/).")
        print("-> Make sure you run this script as an Administrator.")

if __name__ == "__main__":
    main()
