import socket
from asyncio import timeout
from nturl2path import url2pathname
from unittest import result

import requests
from datetime import datetime


PORTS = {
    21 : "FTP",
    22 : "SSH",
    23 : "Telnet",
    25 : "SMTP",
    53 : "DNS",
    80 : "HTTP",
    443 : "HTTPS",
    3306 : "MySQL"
}


def scan_ports(host):
    print("\n[+] Scanning Ports....")
    open_ports = []

    for port in PORTS:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)

            result = s.connect_ex((host, port))

            if result == 0:
                open_ports.append((port, PORTS[port]))

            s.close()


        except Exception:
            pass


    return  open_ports



def check_security_headers(url):
    print("[+] Checking security Headers...")

    required_headers = [
        "Content-Security-Policy",
        "X-Frame_Options",
        "Strict-Transparent-Security",
        "X-Content-Type-Options"
    ]

    missing = []
    server = "Unknown"

    try:
        response = requests.get(url, timeout=5)

        server = response.headers.get("Server", "No Disclosed")

        for header in required_headers:
            if header not in response.headers:
                missing.append(header)



    except Exception as e:
        print("Error: ", e)


    return missing, server




def generate_report(host, open_ports, missing_headers, server):
    print("\n" + "=" * 50)
    print("VULNERABILITY SCAN REPORT")
    print("=" * 50)
    print("Target:", host)
    print("Time:", datetime.now())

    print("\n[OPEN PORTS]")
    if open_ports:
        for port, service in open_ports:
            print(f"{port} - {service}")

    else:
        print("No common port found")

    print("\n[SECURITY HEADER]")
    if missing_headers:
        for header in missing_headers:
            print("Missing: ", header)

    else:
        print("All checked headers present")

    print("\n[SECURITY INFO]")
    print(server)


    print("\n[SUGGESTIONS]")

    if missing_headers:
        print("- Add missing security header")
    print("- Keep server software updated")
    print("- Close unnecessary ports")

    print("=" * 50)





url = input("Enter website url (e.g. https://www.google.com): ")


host = url.replace("https://", "").replace("https://", "").split("/")[0]

ports = scan_ports(host)
missing_headers, server = check_security_headers(url)


generate_report(host, ports, missing_headers, server)






















