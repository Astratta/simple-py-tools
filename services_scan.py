import socket

def get_banner(ip: str, port: int) -> str:
    request_chunk = 2048 ## The chunk of data to read
    response_data = b'' ## The response from the server to decode

    skt = socket.socket()
    #skt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    skt.settimeout(15)

    try:
        skt.connect((ip, port))

        if port in [80, 443]: ## Process the HTTP requests diferently
            ## Carriege Return (CR/ \r) is ASCII byte that moves the cursor to the beginning without advancing to the next line
            ## Line Feed (LF/ \n) is an ASCII byte the moves the cursor to the next line without returning to the beginning of the line
            ## LF is a new liner to Unix based systems and CR+LF is a new liner for non-Unix based systems
            ## They're used here to interpret the response from the HTTP server
            
            cr_lf = "\r\n" 
            lf_lf = "\n\n"
            crlf_crlf = cr_lf + cr_lf

            request_data = f"GET / HTTP/1.1 {cr_lf}" ## The request data to a HTTP server
            request_data += f"Host: {ip}:{port}{cr_lf}" ## Setting a host header
            request_data += f"Connection: close{cr_lf}" ## Set connection header to Close; adding it to request data

            ## headers join together with `\r\n` and ends with `\r\n\r\n`
            ## adding '\r\n' to end of req_data
            request_data += cr_lf

            response_separator = "" ## Separator for Header and Body

            skt.sendall(request_data.encode()) ## Using sendall() because send() may send only partial content

            while True: ## skt.recv(n) may receive less than n bytes, that's why it is in an while block
                try:
                    chunk = skt.recv(request_chunk)
                    response_data += chunk
                except socket.error:
                    break
                if not chunk:
                    break
            
            if response_data: ## Check if we have a response
                response_data = response_data.decode()
            else:
                return "No response from the HTTP Server"
            
            if crlf_crlf in response_data: ## Detect header and body separated that is '\r\n\r\n' or '\n\n'
                response_separator = crlf_crlf
            elif lf_lf in response_data:
                response_separator = lf_lf
            
            content = response_data.split(response_separator) ## Split header and data section from. Format HEAD\r\n\r\nBODY or HEAD\n\nBODY
            banner = "".join(content[:1])

            for i in banner.split(cr_lf):
                if "Server" in i:
                    banner = i
                    break

            return banner
        
        response_data = skt.recv(request_chunk)
        banner = str(response_data.decode())
        banner = banner.replace("\n","")

        return banner
    except:
        return "Couldnt get service banner"
    finally:
        skt.close()
    

## Getting HTTP Banner using sockets: https://stackoverflow.com/questions/22746480/banner-grabbing-http