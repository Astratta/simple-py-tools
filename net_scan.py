import scapy.all as scapy 
import socket
import argparse

def get_net_clients(network: str, interface: str) -> list[dict] | None:  
    request = scapy.ARP() ## Setting up an ARP request over the network
    request.pdst = network ## Setting up the network to scan

    broadcast = scapy.Ether()  ## Setting up the network interface    
    broadcast.dst = "ff:ff:ff:ff:ff:ff" ## Setting up the MAC addresses of the targets
        
    request_broadcast = broadcast / request ## Combining the Ethernet Frame and the ARP request into a single packet

    try:
        packets = scapy.srp(request_broadcast, timeout = 20, iface=interface)[0] ## Sending the request and saving packets with an answer
    except:
        return print("Interface doesnt exist")

    clients = []
    for i, packet in enumerate(packets, 1):
        ## The index 1 element of the packet to access the answer from the client
        try:
            client = {
                "hostname": socket.gethostbyaddr(packet[1].psrc)[0], ## Socket lib to get the hostname by ip
                "ip": packet[1].psrc, ## Client Ip
                "mac": packet[1].hwsrc ## Client MAC
            }
        except:
            client = { "hostname": "UNKNOWN", "ip": packet[1].psrc, "mac": packet[1].hwsrc}
        finally:
            clients.append(client)
    
    if clients: 
        return clients

def argparser() -> argparse.Namespace:
    parser = argparse.ArgumentParser()

    try:
        parser.add_argument("-n", "--netid", type=str, help="Network ID with mask, ex: x.x.x.x/x")
        parser.add_argument("-i", "--interface", type=str, help="The network interface to launch the scan")
    except argparse.ArgumentError as e:
        print(e)

    return parser.parse_args()

def main() -> None:
    args = argparser()
    try:
        clients = get_net_clients(args.netid, args.interface)
        if clients:
            for client in clients:
                print(client)
    except:
        print("Incorrect args, type net-scan --help")

if __name__ == "__main__":
    main()
    