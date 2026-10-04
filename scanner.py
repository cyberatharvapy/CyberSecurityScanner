import nmap


def scan_ports(target):

    scanner = nmap.PortScanner()

    print("\n" + "=" * 60)
    print("1. PORT & SERVICE SCANNING")
    print("=" * 60)

    print(f"[+] Target: {target}")
    print("[+] Starting Nmap scan...\n")

    scanner.scan(target, arguments="-sV")

    results = []

    for host in scanner.all_hosts():

        print(f"Host: {host}")
        print(f"State: {scanner[host].state()}")

        for protocol in scanner[host].all_protocols():

            for port in sorted(scanner[host][protocol].keys()):

                service = scanner[host][protocol][port]

                result = {
                    "port": port,
                    "protocol": protocol,
                    "state": service.get("state"),
                    "service": service.get("name", "Unknown"),
                    "product": service.get("product", "Unknown"),
                    "version": service.get("version", "Unknown")
                }

                results.append(result)

                print(
                    f"[+] Port {port} | "
                    f"{result['state']} | "
                    f"{result['service']} | "
                    f"{result['version']}"
                )

    print(f"\n[+] Scan completed.")
    print(f"[+] Open/Detected ports: {len(results)}")

    return results