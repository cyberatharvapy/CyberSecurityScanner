import requests


SECURITY_HEADERS = {
    "Content-Security-Policy":
        "Helps reduce certain content-injection risks.",

    "X-Frame-Options":
        "Helps protect against clickjacking.",

    "X-Content-Type-Options":
        "Helps prevent MIME-type sniffing.",

    "Strict-Transport-Security":
        "Helps enforce HTTPS.",

    "Referrer-Policy":
        "Controls referrer information.",

    "Permissions-Policy":
        "Controls access to browser features."
}


def scan_http(url):

    print("\n" + "=" * 60)
    print("4. HTTP SECURITY ANALYSIS")
    print("=" * 60)

    print(f"[+] Target: {url}")

    try:

        response = requests.get(
            url,
            timeout=10,
            allow_redirects=True
        )

    except requests.RequestException as error:

        print(f"[!] HTTP connection failed: {error}")

        return {
            "reachable": False,
            "missing_headers": [],
            "status_code": None
        }

    print(f"[+] Status Code: {response.status_code}")
    print(f"[+] Final URL: {response.url}")

    missing_headers = []

    for header in SECURITY_HEADERS:

        if header in response.headers:

            print(f"[+] {header}: PRESENT")

        else:

            print(f"[-] {header}: MISSING")

            missing_headers.append(header)

    print(
        f"\n[+] Missing security headers: "
        f"{len(missing_headers)}"
    )

    return {
        "reachable": True,
        "status_code": response.status_code,
        "url": response.url,
        "server": response.headers.get("Server", "Not disclosed"),
        "missing_headers": missing_headers
    }