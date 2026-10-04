# Basic risk analyzer

RISKY_PORTS = {
    21: ("FTP", "Medium"),
    23: ("Telnet", "High"),
    135: ("MSRPC", "Medium"),
    139: ("NetBIOS", "Medium"),
    445: ("SMB", "High"),
    3306: ("MySQL", "High"),
    3389: ("RDP", "High"),
}


def analyze_risks(scan_results):

    findings = []

    print("\n" + "=" * 60)
    print("2. RISK ANALYSIS")
    print("=" * 60)

    for result in scan_results:

        port = result["port"]
        service = result["service"]

        if port in RISKY_PORTS:

            name, risk = RISKY_PORTS[port]

            finding = {
                "port": port,
                "service": name,
                "risk": risk,
                "description": f"{name} service detected on port {port}."
            }

            findings.append(finding)

            print(f"[!] {risk} risk: Port {port} ({name})")

        else:

            print(
                f"[+] Port {port} ({service}) "
                f"- no basic risk rule matched"
            )

    return findings