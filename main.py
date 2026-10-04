import argparse
from scanner import scan_ports
from risk_analyzer import analyze_risks
from vulnerability_scanner import vulnerability_scan
from cve_scanner import scan_for_cves
from http_scanner import scan_http
from report_generator import generate_report


def main():

    print("=" * 60)
    print("       CYBER SECURITY VULNERABILITY SCANNER")
    print("=" * 60)

    parser = argparse.ArgumentParser(
    description="Cyber Security Vulnerability Scanner"
)

    parser.add_argument( 
    "--target",
    required=True,
    help="Authorized IP address or hostname to scan"
)

    args = parser.parse_args()

    target = args.target
    
    # 1. PORT SCANNING
    

    scan_results = scan_ports(target)

    
    # 2. RISK ANALYSIS
    

    risk_findings = analyze_risks(scan_results)

    
    # 3. VULNERABILITY SCANNING
    

    vulnerability_findings = vulnerability_scan(target)

    
    # 4. CVE Intellegence

    cve_findings = scan_for_cves(scan_results)

    # 5. HTTP  Scaning
    

    http_result = None

    http_ports = [80, 443, 8000, 8080]

    for result in scan_results:

        if (
            result["port"] in http_ports
            and result["state"] == "open"
        ):

            if result["port"] == 443:
                url = f"https://{target}"

            else:
                url = f"http://{target}:{result['port']}"

            http_result = scan_http(url)

            break

            
    # 6. GENERATE HTML REPORT
    

    print("\n" + "=" * 60)
    print("5. REPORT GENERATION")
    print("=" * 60)

    generate_report(
        target,
        scan_results,
        risk_findings,
        vulnerability_findings,
        cve_findings,
        http_result
    )

    
    # FINAL SUMMARY
    

    print("\n" + "=" * 60)
    print("             SCAN SUMMARY")
    print("=" * 60)

    print(f"Target: {target}")

    print(
        f"\nOpen/Detected Ports: "
        f"{len(scan_results)}"
    )

    print(
        f"Basic Risk Findings: "
        f"{len(risk_findings)}"
    )

    print(
        f"NSE Findings: "
        f"{len(vulnerability_findings)}"
    )

    if http_result:

        print(
            f"Missing HTTP Security Headers: "
            f"{len(http_result['missing_headers'])}"
        )

    else:

        print("HTTP Service: Not detected")

    print("\n[+] Scan completed successfully.")


if __name__ == "__main__":
    main()