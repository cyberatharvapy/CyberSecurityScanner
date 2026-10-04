import requests
from urllib.parse import quote


NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def search_cves(product, version, max_results=5):

    if not product or product == "Unknown":
        return []

    keyword = product

    if version and version != "Unknown":
        keyword = f"{product} {version}"

    print(f"[+] Searching NVD for: {keyword}")

    params = {
        "keywordSearch": keyword,
        "resultsPerPage": max_results
    }

    try:
        response = requests.get(
            NVD_API,
            params=params,
            timeout=15
        )

        response.raise_for_status()

        data = response.json()

    except requests.RequestException as error:

        print(f"[!] NVD request failed: {error}")
        return []

    vulnerabilities = data.get("vulnerabilities", [])

    results = []

    for item in vulnerabilities:

        cve = item.get("cve", {})

        cve_id = cve.get(
            "id",
            "Unknown"
        )

        descriptions = cve.get(
            "descriptions",
            []
        )

        description = "No description available."

        for desc in descriptions:

            if desc.get("lang") == "en":

                description = desc.get(
                    "value",
                    description
                )

                break

        metrics = cve.get(
            "metrics",
            {}
        )

        severity = "Unknown"
        score = "Unknown"

        if metrics.get("cvssMetricV31"):

            cvss = metrics["cvssMetricV31"][0]

            cvss_data = cvss.get(
                "cvssData",
                {}
            )

            severity = cvss_data.get(
                "baseSeverity",
                "Unknown"
            )

            score = cvss_data.get(
                "baseScore",
                "Unknown"
            )

        elif metrics.get("cvssMetricV30"):

            cvss = metrics["cvssMetricV30"][0]

            cvss_data = cvss.get(
                "cvssData",
                {}
            )

            severity = cvss_data.get(
                "baseSeverity",
                "Unknown"
            )

            score = cvss_data.get(
                "baseScore",
                "Unknown"
            )

        results.append({
            "id": cve_id,
            "severity": severity,
            "score": score,
            "description": description
        })

    return results


def scan_for_cves(scan_results):

    print("\n" + "=" * 60)
    print("5. CVE INTELLIGENCE")
    print("=" * 60)

    findings = []

    # Avoid repeated searches for the same product/version
    checked = set()

    for result in scan_results:

        product = result.get(
            "product",
            "Unknown"
        )

        version = result.get(
            "version",
            "Unknown"
        )

        key = (product, version)

        if key in checked:
            continue

        checked.add(key)

        cves = search_cves(
            product,
            version
        )

        for cve in cves:

            finding = {
                "port": result.get("port"),
                "service": result.get("service"),
                "product": product,
                "version": version,
                "cve": cve["id"],
                "severity": cve["severity"],
                "score": cve["score"],
                "description": cve["description"]
            }

            findings.append(finding)

            print(
                f"[!] Potential match: "
                f"{cve['id']} | "
                f"{cve['severity']} | "
                f"CVSS {cve['score']}"
            )

    if not findings:

        print("[+] No potential CVE matches found.")

    return findings