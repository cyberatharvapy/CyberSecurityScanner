from datetime import datetime
from pathlib import Path
import html
import re


# ============================================================
# SECURITY REPORT GENERATOR
# ============================================================

REPORT_DIR = Path("reports")
REPORT_FILE = REPORT_DIR / "security_report.html"


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def safe(value):
    """Safely convert a value to HTML text."""
    if value is None:
        return "N/A"

    return html.escape(str(value))


def risk_class(level):
    """Return CSS class based on risk level."""
    level = str(level).lower()

    if "critical" in level:
        return "critical"
    elif "high" in level:
        return "high"
    elif "medium" in level or "moderate" in level:
        return "medium"
    elif "low" in level:
        return "low"

    return "info"


def get_cve_url(cve_id):
    """
    Generate an NVD URL only for a valid CVE ID.
    """
    if not cve_id:
        return "#"

    cve_id = str(cve_id).strip()

    if re.match(r"^CVE-\d{4}-\d+$", cve_id):
        return f"https://nvd.nist.gov/vuln/detail/{cve_id}"

    return "#"

def get_risk_badge(level):
    """Create a styled risk badge."""
    css = risk_class(level)
    return f'<span class="badge {css}">{safe(level)}</span>'


# ============================================================
# MAIN REPORT FUNCTION
# ============================================================

def generate_report(
    target,
    scan_results,
    risk_findings,
    vulnerability_findings,
    cve_findings,
    http_result
):
    """
    Generate the complete HTML security assessment report.
    """

    # --------------------------------------------------------
    # Create report directory
    # --------------------------------------------------------

    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    # --------------------------------------------------------
    # Basic information
    # --------------------------------------------------------

    generated_at = datetime.now().strftime(
        "%d %B %Y, %I:%M:%S %p"
    )

    total_ports = len(scan_results)
    total_risks = len(risk_findings)
    total_nse = len(vulnerability_findings)
    total_cves = len(cve_findings)

    missing_headers = []

    if http_result:
        missing_headers = http_result.get(
            "missing_headers",
            []
        )

    total_missing_headers = len(missing_headers)

    # ========================================================
    # RISK SCORE
    # ========================================================

    risk_score = 0

    # Basic port risk
    for finding in risk_findings:

        risk = str(
            finding.get("risk", "")
        ).lower()

        if risk == "critical":
            risk_score += 25

        elif risk == "high":
            risk_score += 20

        elif risk == "medium":
            risk_score += 10

        elif risk == "low":
            risk_score += 5

    # NSE vulnerability findings
    for finding in vulnerability_findings:

        output = str(
            finding.get("output", "")
        ).lower()

        if "critical" in output:
            risk_score += 25

        elif "high" in output:
            risk_score += 20

        elif "medium" in output:
            risk_score += 10

        elif "low" in output:
            risk_score += 5

        else:
            # Generic NSE finding
            risk_score += 10

    # CVE findings
    for finding in cve_findings:

        severity = str(
            finding.get("severity", "")
        ).lower()

        if severity == "critical":
            risk_score += 25

        elif severity == "high":
            risk_score += 20

        elif severity == "medium":
            risk_score += 10

        elif severity == "low":
            risk_score += 5

    # HTTP security headers
    # These are configuration weaknesses rather
    # than confirmed vulnerabilities.
    risk_score += min(
        total_missing_headers * 3,
        15
    )

    # Maximum score = 100
    risk_score = min(
        max(risk_score, 0),
        100
    )

    # --------------------------------------------------------
    # Risk classification
    # --------------------------------------------------------

    if risk_score >= 70:
        risk_level = "Critical"

    elif risk_score >= 40:
        risk_level = "High"

    elif risk_score >= 20:
        risk_level = "Moderate"

    else:
        risk_level = "Low"

    risk_css = risk_class(risk_level)

    # ========================================================
    # PORT TABLE
    # ========================================================

    port_rows = ""

    for result in scan_results:

        port_rows += f"""
        <tr>
            <td>{safe(result.get("port"))}</td>

            <td>
                {safe(result.get("protocol"))}
            </td>

            <td>
                <span class="status-open">
                    {safe(result.get("state"))}
                </span>
            </td>

            <td>
                {safe(result.get("service"))}
            </td>

            <td>
                {safe(result.get("product"))}
            </td>

            <td>
                {safe(result.get("version"))}
            </td>
        </tr>
        """

    if not port_rows:

        port_rows = """
        <tr>
            <td colspan="6">
                No ports were detected.
            </td>
        </tr>
        """

    # ========================================================
    # RISK FINDINGS TABLE
    # ========================================================

    risk_rows = ""

    for finding in risk_findings:

        risk = finding.get(
            "risk",
            "Unknown"
        )

        risk_rows += f"""
        <tr>

            <td>
                {safe(finding.get("port"))}
            </td>

            <td>
                {safe(finding.get("service"))}
            </td>

            <td>
                {get_risk_badge(risk)}
            </td>

            <td>
                {safe(finding.get("description"))}
            </td>

        </tr>
        """

    if not risk_rows:

        risk_rows = """
        <tr>
            <td colspan="4">
                No basic risk rules were triggered.
            </td>
        </tr>
        """

    # ========================================================
    # NSE VULNERABILITY TABLE
    # ========================================================

    nse_rows = ""

    for finding in vulnerability_findings:

        output = finding.get(
            "output",
            "No output available."
        )

        nse_rows += f"""
        <tr>

            <td>
                {safe(finding.get("port"))}
            </td>

            <td>
                {safe(finding.get("script"))}
            </td>

            <td class="preformatted">
                {safe(output)}
            </td>

        </tr>
        """

    if not nse_rows:

        nse_rows = """
        <tr>
            <td colspan="3">
                No NSE vulnerability findings detected.
            </td>
        </tr>
        """

    # ========================================================
    # CVE TABLE
    # ========================================================

    cve_rows = ""

    for finding in cve_findings:

        cve_id = finding.get(
            "cve",
            "Unknown"
        )

        cve_url = get_cve_url(cve_id)

        cve_rows += f"""
        <tr>

            <td>
                {safe(finding.get("port"))}
            </td>

            <td>
                {safe(finding.get("product"))}
            </td>

            <td>
                {safe(finding.get("version"))}
            </td>

            <td>
                <a
                    href="{safe(cve_url)}"
                    target="_blank"
                    rel="noopener noreferrer"
                    class="cve-link"
                >
                    {safe(cve_id)}
                </a>
            </td>

            <td>
                {get_risk_badge(
                    finding.get("severity", "Unknown")
                )}
            </td>

            <td>
                <strong>
                    {safe(finding.get("score"))}
                </strong>
            </td>

            <td>
                {safe(
                    finding.get(
                        "description",
                        "No description available."
                    )
                )}
            </td>

        </tr>
        """

    if not cve_rows:

        cve_rows = """
        <tr>
            <td colspan="7">
                No potential CVE matches detected.
            </td>
        </tr>
        """

    # ========================================================
    # HTTP SECURITY TABLE
    # ========================================================

    http_rows = ""

    if http_result and http_result.get("reachable"):

        http_url = http_result.get(
            "url",
            "N/A"
        )

        status_code = http_result.get(
            "status_code",
            "N/A"
        )

        server = http_result.get(
            "server",
            "Not disclosed"
        )

        http_rows += f"""
        <tr>
            <td>Target URL</td>
            <td>{safe(http_url)}</td>
        </tr>

        <tr>
            <td>HTTP Status</td>
            <td>{safe(status_code)}</td>
        </tr>

        <tr>
            <td>Server</td>
            <td>{safe(server)}</td>
        </tr>
        """

    else:

        http_rows = """
        <tr>
            <td>Status</td>
            <td>
                HTTP service was not reachable or was not scanned.
            </td>
        </tr>
        """

    # ========================================================
    # MISSING SECURITY HEADERS
    # ========================================================

    header_rows = ""

    for header in missing_headers:

        header_rows += f"""
        <tr>
            <td>
                {safe(header)}
            </td>

            <td>
                <span class="badge medium">
                    Missing
                </span>
            </td>

            <td>
                Review the web application's security
                configuration for this header.
            </td>
        </tr>
        """

    if not header_rows:

        header_rows = """
        <tr>
            <td colspan="3">
                No missing security headers detected.
            </td>
        </tr>
        """

    # ========================================================
    # RECOMMENDATIONS
    # ========================================================

    recommendations = []

    if risk_findings:

        recommendations.append(
            "Review all services identified by the risk "
            "analysis and disable unnecessary services."
        )

    if vulnerability_findings:

        recommendations.append(
            "Manually verify NSE vulnerability findings "
            "before taking remediation action."
        )

    if cve_findings:

        recommendations.append(
            "Verify detected product versions against the "
            "affected-version ranges in the referenced CVEs."
        )

    if 445 in [
        item.get("port")
        for item in risk_findings
    ]:

        recommendations.append(
            "Review SMB exposure on port 445 and restrict "
            "access to trusted networks where possible."
        )

    if 23 in [
        item.get("port")
        for item in risk_findings
    ]:

        recommendations.append(
            "Avoid Telnet where possible and replace it "
            "with a secure protocol such as SSH."
        )

    if missing_headers:

        recommendations.append(
            "Review the missing HTTP security headers and "
            "configure appropriate values for the application."
        )

    if not recommendations:

        recommendations.append(
            "No immediate issues were identified by the "
            "configured detection rules. Continue regular "
            "security assessments."
        )

    recommendation_items = ""

    for recommendation in recommendations:

        recommendation_items += f"""
        <li>
            {safe(recommendation)}
        </li>
        """

    # ========================================================
    # EXECUTIVE SUMMARY
    # ========================================================

    if risk_level == "Critical":

        summary_text = (
            "The assessment identified multiple security "
            "indicators requiring immediate review."
        )

    elif risk_level == "High":

        summary_text = (
            "The assessment identified significant security "
            "indicators that should be investigated and "
            "remediated."
        )

    elif risk_level == "Moderate":

        summary_text = (
            "The assessment identified several security "
            "configuration or exposure concerns that should "
            "be reviewed."
        )

    else:

        summary_text = (
            "The assessment did not identify significant "
            "issues using the currently configured checks."
        )

    # ========================================================
    # HTML DOCUMENT
    # ========================================================

    html_content = f"""
<!DOCTYPE html>

<html lang="en">

<head>

<meta charset="UTF-8">

<meta
    name="viewport"
    content="width=device-width, initial-scale=1.0"
>

<title>
    CyberSecurity Scanner Report
</title>


<style>

/* =========================================================
   GLOBAL
   ========================================================= */

* {{
    box-sizing: border-box;
}}

body {{
    margin: 0;
    padding: 0;

    font-family:
        Arial,
        Helvetica,
        sans-serif;

    background: #f1f5f9;

    color: #1e293b;

    line-height: 1.6;
}}


/* =========================================================
   HEADER
   ========================================================= */

.header {{

    background:
        linear-gradient(
            135deg,
            #0f172a,
            #1e3a8a
        );

    color: white;

    padding: 40px 20px;

    text-align: center;
}}

.header h1 {{

    margin: 0;

    font-size: 34px;

    letter-spacing: 0.5px;
}}

.header p {{

    margin: 8px 0 0;

    opacity: 0.9;

    font-size: 15px;
}}


/* =========================================================
   MAIN CONTAINER
   ========================================================= */

.container {{

    max-width: 1400px;

    margin: 30px auto;

    padding: 0 20px;
}}


/* =========================================================
   INFO BAR
   ========================================================= */

.info-bar {{

    background: white;

    border-radius: 12px;

    padding: 20px;

    margin-bottom: 25px;

    box-shadow:
        0 4px 12px rgba(
            15,
            23,
            42,
            0.08
        );

    display: grid;

    grid-template-columns:
        repeat(
            auto-fit,
            minmax(
                200px,
                1fr
            )
        );

    gap: 15px;
}}

.info-item strong {{

    display: block;

    font-size: 12px;

    color: #64748b;

    text-transform: uppercase;

    margin-bottom: 4px;
}}


/* =========================================================
   RISK DASHBOARD
   ========================================================= */

.dashboard {{

    display: grid;

    grid-template-columns:
        minmax(250px, 1fr)
        2fr;

    gap: 20px;

    margin-bottom: 25px;
}}

.score-card {{

    background: white;

    border-radius: 16px;

    padding: 30px;

    text-align: center;

    box-shadow:
        0 4px 12px rgba(
            15,
            23,
            42,
            0.08
        );
}}

.score-title {{

    font-size: 14px;

    color: #64748b;

    text-transform: uppercase;

    font-weight: bold;
}}

.score {{

    font-size: 70px;

    font-weight: 800;

    margin: 10px 0;
}}

.score-label {{

    font-size: 20px;

    font-weight: bold;
}}


/* =========================================================
   RISK COLORS
   ========================================================= */

.critical {{
    color: #b91c1c;
    background: #fee2e2;
    border-color: #fecaca;
}}

.high {{
    color: #c2410c;
    background: #ffedd5;
    border-color: #fed7aa;
}}

.medium {{
    color: #a16207;
    background: #fef9c3;
    border-color: #fde68a;
}}

.low {{
    color: #15803d;
    background: #dcfce7;
    border-color: #bbf7d0;
}}

.info {{
    color: #1d4ed8;
    background: #dbeafe;
    border-color: #bfdbfe;
}}


/* =========================================================
   SCORE BAR
   ========================================================= */

.score-bar-container {{

    background: #e2e8f0;

    height: 18px;

    border-radius: 20px;

    overflow: hidden;

    margin-top: 20px;
}}

.score-bar {{

    height: 100%;

    width: {risk_score}%;

    border-radius: 20px;

    background:
        linear-gradient(
            90deg,
            #22c55e,
            #eab308,
            #f97316,
            #dc2626
        );
}}


/* =========================================================
   SUMMARY CARDS
   ========================================================= */

.summary-grid {{

    display: grid;

    grid-template-columns:
        repeat(
            auto-fit,
            minmax(
                160px,
                1fr
            )
        );

    gap: 15px;
}}

.summary-card {{

    background: white;

    padding: 20px;

    border-radius: 12px;

    text-align: center;

    box-shadow:
        0 4px 12px rgba(
            15,
            23,
            42,
            0.06
        );
}}

.summary-number {{

    font-size: 32px;

    font-weight: bold;

    margin-bottom: 4px;
}}

.summary-label {{

    color: #64748b;

    font-size: 13px;
}}


/* =========================================================
   SECTIONS
   ========================================================= */

.section {{

    background: white;

    margin-top: 25px;

    border-radius: 12px;

    padding: 25px;

    box-shadow:
        0 4px 12px rgba(
            15,
            23,
            42,
            0.06
        );

    overflow-x: auto;
}}

.section h2 {{

    margin-top: 0;

    color: #0f172a;

    border-bottom:
        2px solid #e2e8f0;

    padding-bottom: 10px;
}}

.section-description {{

    color: #64748b;

    font-size: 14px;

    margin-bottom: 20px;
}}


/* =========================================================
   TABLES
   ========================================================= */

table {{

    width: 100%;

    border-collapse: collapse;

    min-width: 700px;
}}

th {{

    background: #0f172a;

    color: white;

    text-align: left;

    padding: 12px;

    font-size: 13px;
}}

td {{

    padding: 12px;

    border-bottom:
        1px solid #e2e8f0;

    vertical-align: top;

    font-size: 13px;
}}

tr:hover td {{

    background: #f8fafc;
}}


/* =========================================================
   BADGES
   ========================================================= */

.badge {{

    display: inline-block;

    padding: 4px 10px;

    border-radius: 20px;

    font-size: 11px;

    font-weight: bold;

    border: 1px solid;
}}

.status-open {{

    display: inline-block;

    background: #dcfce7;

    color: #166534;

    padding: 4px 9px;

    border-radius: 15px;

    font-size: 11px;

    font-weight: bold;
}}


/* =========================================================
   CVE LINK
   ========================================================= */

.cve-link {{

    color: #2563eb;

    text-decoration: none;

    font-weight: bold;
}}

.cve-link:hover {{

    text-decoration: underline;
}}


/* =========================================================
   CODE / NSE OUTPUT
   ========================================================= */

.preformatted {{

    white-space: pre-wrap;

    word-break: break-word;

    font-family:
        Consolas,
        "Courier New",
        monospace;

    font-size: 12px;

    background: #f8fafc;
}}


/* =========================================================
   RECOMMENDATIONS
   ========================================================= */

.recommendations {{

    margin: 0;

    padding-left: 22px;
}}

.recommendations li {{

    margin-bottom: 12px;

    padding-left: 5px;
}}


/* =========================================================
   NOTICE
   ========================================================= */

.notice {{

    background: #eff6ff;

    border-left:
        4px solid #2563eb;

    padding: 15px;

    margin-top: 15px;

    font-size: 13px;
}}

.warning {{

    background: #fff7ed;

    border-left:
        4px solid #f97316;

    padding: 15px;

    margin-top: 15px;

    font-size: 13px;
}}


/* =========================================================
   FOOTER
   ========================================================= */

.footer {{

    text-align: center;

    color: #64748b;

    font-size: 12px;

    padding: 30px 20px;
}}


/* =========================================================
   RESPONSIVE
   ========================================================= */

@media(max-width: 800px) {{

    .dashboard {{

        grid-template-columns: 1fr;

    }}

    .header h1 {{

        font-size: 26px;

    }}

    .score {{

        font-size: 55px;

    }}
}}

</style>

</head>


<body>


<!-- ======================================================
     HEADER
     ====================================================== -->

<div class="header">

    <h1>
        CyberSecurity Scanner
    </h1>

    <p>
        Automated Security Assessment Report
    </p>

</div>


<div class="container">


<!-- ======================================================
     ASSESSMENT INFORMATION
     ====================================================== -->

<div class="info-bar">

    <div class="info-item">

        <strong>
            Target
        </strong>

        {safe(target)}

    </div>


    <div class="info-item">

        <strong>
            Generated
        </strong>

        {safe(generated_at)}

    </div>


    <div class="info-item">

        <strong>
            Assessment Type
        </strong>

        Network + Web Security Assessment

    </div>


    <div class="info-item">

        <strong>
            Tool
        </strong>

        CyberSecurity Scanner

    </div>

</div>


<!-- ======================================================
     RISK DASHBOARD
     ====================================================== -->

<div class="dashboard">


    <div class="score-card">

        <div class="score-title">
            Overall Risk Score
        </div>

        <div class="score">
            {risk_score}
        </div>

        <div class="score-label">
            <span class="badge {risk_css}">
                {safe(risk_level)}
            </span>
        </div>

        <div class="score-bar-container">

            <div class="score-bar"></div>

        </div>

        <p class="section-description">

            Score is a heuristic based on detected
            services, configured risk rules, NSE
            findings, potential CVE matches and
            HTTP security configuration.

        </p>

    </div>


    <div class="score-card">

        <div class="score-title">
            Executive Summary
        </div>

        <p style="text-align:left;">

            {safe(summary_text)}

        </p>

        <div class="notice">

            <strong>
                Important:
            </strong>

            This report is an automated assessment.
            Findings should be manually verified before
            making security decisions.

        </div>

    </div>

</div>


<!-- ======================================================
     SUMMARY STATISTICS
     ====================================================== -->

<div class="summary-grid">


    <div class="summary-card">

        <div class="summary-number">
            {total_ports}
        </div>

        <div class="summary-label">
            Detected Ports
        </div>

    </div>


    <div class="summary-card">

        <div class="summary-number">
            {total_risks}
        </div>

        <div class="summary-label">
            Risk Findings
        </div>

    </div>


    <div class="summary-card">

        <div class="summary-number">
            {total_nse}
        </div>

        <div class="summary-label">
            NSE Findings
        </div>

    </div>


    <div class="summary-card">

        <div class="summary-number">
            {total_cves}
        </div>

        <div class="summary-label">
            Potential CVEs
        </div>

    </div>


    <div class="summary-card">

        <div class="summary-number">
            {total_missing_headers}
        </div>

        <div class="summary-label">
            Missing HTTP Headers
        </div>

    </div>


</div>


<!-- ======================================================
     SECTION 1
     PORT SCANNING
     ====================================================== -->

<div class="section">

<h2>
    1. Port & Service Scanning
</h2>

<p class="section-description">

    Services and ports detected by Nmap
    service/version detection.

</p>


<table>

<tr>

<th>
    Port
</th>

<th>
    Protocol
</th>

<th>
    State
</th>

<th>
    Service
</th>

<th>
    Product
</th>

<th>
    Version
</th>

</tr>

{port_rows}

</table>

</div>


<!-- ======================================================
     SECTION 2
     RISK ANALYSIS
     ====================================================== -->

<div class="section">

<h2>
    2. Risk Analysis
</h2>

<p class="section-description">

    Findings generated using the scanner's
    configured basic risk rules.

</p>


<table>

<tr>

<th>
    Port
</th>

<th>
    Service
</th>

<th>
    Risk
</th>

<th>
    Description
</th>

</tr>

{risk_rows}

</table>

</div>


<!-- ======================================================
     SECTION 3
     NSE VULNERABILITY
     ====================================================== -->

<div class="section">

<h2>
    3. NSE Vulnerability Scanning
</h2>

<p class="section-description">

    Results returned by Nmap NSE vulnerability
    scripts.

</p>


<table>

<tr>

<th>
    Port
</th>

<th>
    NSE Script
</th>

<th>
    Output
</th>

</tr>

{nse_rows}

</table>


<div class="warning">

<strong>
    Important:
</strong>

The absence of NSE findings does not prove that
the target is vulnerability-free.

</div>

</div>


<!-- ======================================================
     SECTION 4
     CVE INTELLIGENCE
     ====================================================== -->

<div class="section">

<h2>
    4. CVE Intelligence
</h2>

<p class="section-description">

    Potential CVE matches identified using detected
    product/service information and NVD data.

</p>


<table>

<tr>

<th>
    Port
</th>

<th>
    Product
</th>

<th>
    Version
</th>

<th>
    CVE
</th>

<th>
    Severity
</th>

<th>
    CVSS
</th>

<th>
    Description
</th>

</tr>

{cve_rows}

</table>


<div class="warning">

<strong>
    Important:
</strong>

CVE results are potential matches only.
A keyword/product match does not establish that
the detected software is vulnerable.

Always verify the exact product, version,
configuration and affected-version range.

</div>

</div>


<!-- ======================================================
     SECTION 5
     HTTP ANALYSIS
     ====================================================== -->

<div class="section">

<h2>
    5. HTTP Security Analysis
</h2>

<p class="section-description">

    HTTP response and security-header configuration
    analysis.

</p>


<table>

<tr>

<th>
    Property
</th>

<th>
    Result
</th>

</tr>

{http_rows}

</table>

</div>


<!-- ======================================================
     SECTION 6
     HTTP SECURITY HEADERS
     ====================================================== -->

<div class="section">

<h2>
    6. HTTP Security Headers
</h2>

<p class="section-description">

    Security headers that were not present in the
    HTTP response.

</p>


<table>

<tr>

<th>
    Header
</th>

<th>
    Status
</th>

<th>
    Recommendation
</th>

</tr>

{header_rows}

</table>


<div class="notice">

<strong>
    Note:
</strong>

Missing security headers represent configuration
weaknesses and do not automatically mean that the
application is vulnerable.

</div>

</div>


<!-- ======================================================
     SECTION 7
     RECOMMENDATIONS
     ====================================================== -->

<div class="section">

<h2>
    7. Security Recommendations
</h2>

<p class="section-description">

    Recommended actions based on the automated
    assessment results.

</p>


<ul class="recommendations">

{recommendation_items}

</ul>

</div>


<!-- ======================================================
     SECTION 8
     LIMITATIONS
     ====================================================== -->

<div class="section">

<h2>
    8. Assessment Limitations
</h2>

<ul class="recommendations">

<li>
    Automated scanning cannot identify every
    vulnerability.
</li>

<li>
    An open port does not automatically represent
    a vulnerability.
</li>

<li>
    NSE results depend on the scripts supported
    by the installed Nmap version.
</li>

<li>
    CVE results are potential matches and require
    manual verification.
</li>

<li>
    HTTP security-header findings represent
    configuration observations.
</li>

<li>
    The risk score is a heuristic created by this
    scanner and is not equivalent to CVSS.
</li>

<li>
    Testing should only be performed against
    systems for which you have authorization.
</li>

</ul>

</div>


</div>


<!-- ======================================================
     FOOTER
     ====================================================== -->

<div class="footer">

    CyberSecurity Scanner
    <br>

    Automated Security Assessment Report

    <br><br>

    Generated on {safe(generated_at)}

</div>


</body>

</html>
"""

    # ========================================================
    # WRITE REPORT
    # ========================================================

    with open(
        REPORT_FILE,
        "w",
        encoding="utf-8"
    ) as file:

        file.write(html_content)

    # ========================================================
    # CONSOLE OUTPUT
    # ========================================================

    print("\n" + "=" * 60)
    print("REPORT GENERATION")
    print("=" * 60)

    print(
        f"[+] Security report generated successfully."
    )

    print(
        f"[+] Risk Score: {risk_score}/100"
    )

    print(
        f"[+] Risk Level: {risk_level}"
    )

    print(
        f"[+] Report: {REPORT_FILE}"
    )

    return str(REPORT_FILE)