import socket
import argparse
import threading
from queue import Queue
from services_scan import get_banner

def argparser() -> argparse.Namespace:
    parser = argparse.ArgumentParser()

    try:
        parser.add_argument("ip", type=str, help="IP to scan")
        parser.add_argument("-pr", "--port_range", type=int, nargs=2, default=[1, 1000], help="The port range to scan, default 1-1000")
    except argparse.ArgumentError as e:
        print(e)

    return parser.parse_args()

def port_scan(ip: str, port: int, threads_results: Queue) -> None:
    skt = socket.socket(socket.AF_INET, socket.SOCK_STREAM) ## Creating a socket that uses IPv4 addresses (socket.AF_INET) and utilizes the TCP protocol (socket.SOCK_STREAM)
    skt.settimeout(2)
    try: ## Tries to connect, if it does, store the port into the results queue
        skt.connect((ip, port)) 
        threads_results.put(port)
    except:
        pass
    finally:
        skt.close()

def get_open_ports(ip: str, port_range: list[int]) -> list[int]:
    threads_results = Queue() ## Results queue, stores the result of every thread
    threads = [] ## List of running threads

    for port in range(port_range[0], port_range[1]+1):
        t = threading.Thread(target=port_scan, kwargs={"ip": ip, "port": port, "threads_results": threads_results})
        threads.append(t)
        t.start()
    
    for t in threads: ## Block the main code flow to wait all threads to complete
        t.join() 

    open_ports = []

    while not threads_results.empty(): ## Build a list with all open ports
        open_ports.append(threads_results.get())

    return open_ports

def main() -> None:
    args = argparser()
    ports = get_open_ports(args.ip, sorted(args.port_range))

    for port in ports:
        print(f"[+]{args.ip}:{port} >> {get_banner(args.ip, port)}")

if __name__ == "__main__":
    main()