import sys
import subprocess
import threading

def crack(archive_path: str, passwd: str) -> None:
    command = ['7z', 'x', archive_path, '-p' + passwd, '-o*']

    try:
        output = subprocess.check_output(command, stderr=subprocess.STDOUT)
        #output = output.decode("utf-8")
        print(f"\nFOUND PASSWD >> {passwd}\n")
        print("extracting files...")
    except subprocess.CalledProcessError as e:
        pass

def get_file_passwd(archive_path: str, wordlist_path: str) -> None:
    threads = []

    with open(wordlist_path) as wordlist_file:
        wordlist = [passwd.rstrip("\n") for passwd in wordlist_file.readlines()]

    print("trying wordlist...")

    for passwd in wordlist:
        t = threading.Thread(target=crack, kwargs={"archive_path": archive_path, "passwd": passwd})
        threads.append(t)
        t.start()
    
    for t in threads: ## Block the main code flow to wait all threads to complete
        t.join()
    
    print("done")

def main() -> None:
    if len(sys.argv) <= 2:
        print("format >> crack_archive.py archive_path wordlist_path")
    else:
        get_file_passwd(sys.argv[1], sys.argv[2])

if __name__ == "__main__":
    main()

