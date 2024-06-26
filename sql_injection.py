import requests
import argparse
from pprint import pprint
from urllib.parse import urljoin
from bs4 import BeautifulSoup as bs

## Browser simulation
browser = requests.Session()
browser.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.106 Safari/537.36"

def argparser() -> argparse.Namespace | None:
    parser = argparse.ArgumentParser()

    try:
        parser.add_argument("url", type=str, help="url or url list to scan")
    except argparse.ArgumentError as e:
        print(e)

    return parser.parse_args()

def extract_forms(url: str) -> dict:
    page = bs(browser.get(url).content, "html.parser")
    page_forms = page.find_all("form")

    def get_details(form: bs) -> dict:
        details = {}

        ## Get form button
        try: action = form.attrs.get("action").lower() 
        except: action = None

        ## Get HTTP method, default = GET
        method = form.attrs.get("method", "get").lower()

        inputs = []

        ## Get all form fields, names, values and datatypes
        for input_tag in form.find_all("input"):
            input_type = input_tag.attrs.get("type", "text")
            input_name = input_tag.attrs.get("name")
            input_value = input_tag.attrs.get("value")

            inputs.append({"type": input_type, "name": input_name, "value": input_value})
        
        details["action"] = action
        details["method"] = method
        details["inputs"] = inputs

        return details
    
    if page_forms:
        for form in page_forms:
            yield get_details(form)

def is_vulnerable(page: requests.Response) -> bool | None:
    ## Common databases quotation mark error messages

    ## MySQL - "you have an error in your sql syntax;"
    ## SQL Server - "unclosed quotation mark after the character string"
    ## Oracle - "quoted string not properly terminated"

    errors = [
        "you have an error in your sql syntax", 
        "unclosed quotation mark after the character string",
        "quoted string not properly terminated"
    ]

    for error in errors:
        return True if error in page.content.decode().lower() else False
    
def scan(url: str) -> None:
    ## URL tests
    for c in "\"'":
        print(f">> trying url: {url}{c}")
        page = browser.get(url + c)

        if is_vulnerable(page):
            print(f">> SQL Injection vulnerability detected on {url}{c}")
            return
    
    ## Form tests
    for form_details in extract_forms(url):
        for c in "\"'":
            data = {}

            for input_tag in form_details["inputs"]:
                if input_tag["value"] or input_tag["type"] == "hidden":
                    try: data[input_tag["name"]] = input_tag["value"] + c
                    except: pass
                elif input_tag["type"] != "submit":
                    data[input_tag["name"]] = "test" + c
                
            url = urljoin(url, form_details["action"])

            if form_details["method"] == "post":
                page = browser.post(url, data=data)
            elif form_details["method"] == "get":
                page = browser.get(url, params=data)

            if is_vulnerable(page):
                print(f">> SQL Injection vulnerability detected on {url}")
                print("Form:")
                pprint(form_details)
                break
        else:
            print(">> No vulnerabilities or no forms detected")

def main() -> None:
    args = argparser()
    
    try:
        with open(args.url) as urls:
            print(f">> scanning urls on {args.url}")
            for url in urls.readlines():
                scan(url)
    except:
        print(f">> scanning url {args.url}")
        scan(args.url)

if __name__ == "__main__":
    main()