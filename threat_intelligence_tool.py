import base64
import hashlib
import ipaddress
import json
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import requests
from dotenv import load_dotenv


BASE_URL = "https://www.virustotal.com/api/v3"
MAX_ITEMS = 10
MAX_DISPLAYED_STRINGS = 50
MINIMUM_STRING_LENGTH = 4
MAX_DIRECT_UPLOAD_BYTES = 32 * 1024 * 1024
ANALYSIS_POLL_SECONDS = 15
ANALYSIS_MAX_POLLS = 12

load_dotenv()
API_KEY = os.getenv("VT_API_KEY")


SUSPICIOUS_IMPORTS = {
    "CreateRemoteThread": "May support process injection",
    "WriteProcessMemory": "May write code into another process",
    "VirtualAllocEx": "May allocate memory inside another process",
    "VirtualProtect": "May change memory execution permissions",
    "OpenProcess": "May access another running process",
    "CreateProcessA": "May create another process",
    "CreateProcessW": "May create another process",
    "ShellExecuteA": "May launch a file or command",
    "ShellExecuteW": "May launch a file or command",
    "WinExec": "May execute another program",
    "URLDownloadToFileA": "May download a remote file",
    "URLDownloadToFileW": "May download a remote file",
    "InternetOpenA": "May communicate over the internet",
    "InternetOpenW": "May communicate over the internet",
    "InternetOpenUrlA": "May open a remote URL",
    "InternetOpenUrlW": "May open a remote URL",
    "WinHttpOpen": "May perform HTTP communication",
    "WSAStartup": "Initializes Windows network communication",
    "connect": "May connect to a remote network service",
    "send": "May transmit data over a network",
    "recv": "May receive data from a network",
    "RegSetValueA": "May modify the Windows Registry",
    "RegSetValueW": "May modify the Windows Registry",
    "RegCreateKeyA": "May create a Registry key",
    "RegCreateKeyW": "May create a Registry key",
    "CreateServiceA": "May create a Windows service",
    "CreateServiceW": "May create a Windows service",
    "StartServiceA": "May start a Windows service",
    "StartServiceW": "May start a Windows service",
    "GetAsyncKeyState": "May monitor keyboard input",
    "CryptEncrypt": "May encrypt data",
    "CryptDecrypt": "May decrypt data",
}


COMPILER_WORDS = (
    "visual c++",
    "microsoft visual",
    "gcc",
    "mingw",
    "borland",
    "delphi",
    "clang",
    ".net",
)


def format_timestamp(timestamp):
    if not timestamp:
        return "Not available"

    try:
        return datetime.fromtimestamp(
            timestamp,
            timezone.utc,
        ).strftime("%Y-%m-%d %H:%M:%S UTC")
    except (TypeError, ValueError, OSError):
        return "Invalid or unavailable timestamp"


def print_header(title):
    print("\n" + "=" * 72)
    print(title.center(72))
    print("=" * 72)


def print_section(title):
    print(f"\n{title}")
    print("=" * 72)


def unique_items(items):
    seen = set()
    results = []

    for item in items:
        cleaned = str(item).strip()

        if cleaned and cleaned not in seen:
            seen.add(cleaned)
            results.append(cleaned)

    return results


def print_list(items, empty_message="No information available.", limit=MAX_ITEMS):
    items = unique_items(items)

    if not items:
        print(empty_message)
        return

    for item in items[:limit]:
        print(f"- {item}")

    remaining = len(items) - limit

    if remaining > 0:
        print(f"...and {remaining} additional items.")


def print_dictionary(values, empty_message="No information available."):
    if not values:
        print(empty_message)
        return

    for key, value in values.items():
        print(f"- {key}: {value}")


def vt_get(endpoint):
    headers = {
        "accept": "application/json",
        "x-apikey": API_KEY,
    }

    try:
        return requests.get(
            f"{BASE_URL}{endpoint}",
            headers=headers,
            timeout=30,
        )
    except requests.RequestException as error:
        print(f"Network or API error: {error}")
        return None


def handle_response(response):
    if response is None:
        return None

    print(f"\nStatus Code: {response.status_code}")

    if response.status_code == 200:
        return response.json()

    if response.status_code == 400:
        print("VirusTotal rejected the request as invalid.")
    elif response.status_code == 401:
        print("Authentication failed. Check your API key.")
    elif response.status_code == 403:
        print("Access denied by VirusTotal.")
    elif response.status_code == 404:
        print("VirusTotal does not have a report for this indicator.")
    elif response.status_code == 429:
        print("VirusTotal API rate limit reached. Try again later.")
    else:
        print("VirusTotal returned an unexpected response:")
        print(response.text)

    return None


def print_detection_summary(attributes, section_number=None):
    title = "Detection Summary"

    if section_number is not None:
        title = f"{section_number}. Detection Summary"

    print_section(title)

    stats = attributes.get("last_analysis_stats", {})

    if not stats:
        print("No detection statistics are available.")
        return

    print("Malicious:", stats.get("malicious", 0))
    print("Suspicious:", stats.get("suspicious", 0))
    print("Harmless:", stats.get("harmless", 0))
    print("Undetected:", stats.get("undetected", 0))
    print("Timeout:", stats.get("timeout", 0))


def encode_url_id(url):
    encoded = base64.urlsafe_b64encode(
        url.encode("utf-8")
    ).decode("utf-8")

    return encoded.rstrip("=")


def normalize_url(value):
    value = value.strip()

    if not value:
        return ""

    parsed = urlparse(value)

    if not parsed.scheme:
        value = f"https://{value}"

    return value


def analyze_url():
    url = normalize_url(
        input("Enter the complete URL: ")
    )

    if not url:
        print("Error: A URL is required.")
        return

    url_id = encode_url_id(url)
    report = handle_response(
        vt_get(f"/urls/{url_id}")
    )

    if not report:
        return

    attributes = report["data"]["attributes"]

    print_header("VIRUSTOTAL URL ANALYSIS REPORT")

    print_section("1. URL Identity")
    print("URL:", attributes.get("url", url))
    print("Title:", attributes.get("title", "Not available"))
    print(
        "Final URL:",
        attributes.get("last_final_url", "Not available"),
    )
    print(
        "Last analysis:",
        format_timestamp(attributes.get("last_analysis_date")),
    )
    print("Reputation:", attributes.get("reputation", 0))

    print_detection_summary(attributes, 2)

    print_section("3. Categories")
    print_dictionary(
        attributes.get("categories", {}),
        "No URL categories are available.",
    )

    print_section("4. HTTP Information")
    print(
        "HTTP response code:",
        attributes.get("last_http_response_code", "Not available"),
    )
    print(
        "Content length:",
        attributes.get(
            "last_http_response_content_length",
            "Not available",
        ),
    )
    print(
        "Content SHA-256:",
        attributes.get(
            "last_http_response_content_sha256",
            "Not available",
        ),
    )

    print_section("5. Analyst Summary")

    stats = attributes.get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)

    if malicious > 0:
        print("Assessment: The URL has malicious detections.")
        print("Recommended action: Do not visit it from a production system.")
    elif suspicious > 0:
        print("Assessment: The URL has suspicious detections.")
        print("Recommended action: Investigate before visiting.")
    else:
        print("Assessment: No malicious detections were reported.")
        print(
            "Note: A clean VirusTotal result does not guarantee "
            "that a URL is safe."
        )


def analyze_domain():
    domain = input("Enter the domain name: ").strip().lower()

    if not domain:
        print("Error: A domain is required.")
        return

    domain = domain.removeprefix("http://")
    domain = domain.removeprefix("https://")
    domain = domain.split("/")[0]

    report = handle_response(
        vt_get(f"/domains/{domain}")
    )

    if not report:
        return

    attributes = report["data"]["attributes"]

    print_header("VIRUSTOTAL DOMAIN ANALYSIS REPORT")

    print_section("1. Domain Identity")
    print("Domain:", report["data"].get("id", domain))
    print("Reputation:", attributes.get("reputation", 0))
    print("Registrar:", attributes.get("registrar", "Not available"))
    print(
        "Creation date:",
        format_timestamp(attributes.get("creation_date")),
    )
    print(
        "Last modification:",
        format_timestamp(attributes.get("last_modification_date")),
    )
    print(
        "Last analysis:",
        format_timestamp(attributes.get("last_analysis_date")),
    )

    print_detection_summary(attributes, 2)

    print_section("3. Categories")
    print_dictionary(
        attributes.get("categories", {}),
        "No domain categories are available.",
    )

    print_section("4. Network Registration")
    print("WHOIS server:", attributes.get("whois_server", "Not available"))
    print("Regional registry:", attributes.get("rir", "Not available"))
    print(
        "Last DNS records date:",
        format_timestamp(attributes.get("last_dns_records_date")),
    )

    print_section("5. HTTPS Certificate")

    certificate = attributes.get("last_https_certificate", {})
    subject = certificate.get("subject", {})
    issuer = certificate.get("issuer", {})

    print(
        "Certificate subject:",
        subject.get("CN", "Not available"),
    )
    print(
        "Certificate issuer:",
        issuer.get("CN", "Not available"),
    )

    print_section("6. Analyst Summary")

    stats = attributes.get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)

    if malicious > 0:
        print("Assessment: The domain has malicious detections.")
        print("Recommended action: Block or investigate the domain.")
    elif suspicious > 0:
        print("Assessment: The domain has suspicious detections.")
        print("Recommended action: Investigate before trusting it.")
    else:
        print("Assessment: No malicious detections were reported.")
        print(
            "Note: Reputation can change, and a clean report "
            "does not guarantee safety."
        )


def analyze_ip():
    ip_value = input("Enter the IP address: ").strip()

    try:
        ipaddress.ip_address(ip_value)
    except ValueError:
        print("Error: Enter a valid IPv4 or IPv6 address.")
        return

    report = handle_response(
        vt_get(f"/ip_addresses/{ip_value}")
    )

    if not report:
        return

    attributes = report["data"]["attributes"]

    print_header("VIRUSTOTAL IP ADDRESS ANALYSIS REPORT")

    print_section("1. IP Identity")
    print("IP address:", report["data"].get("id", ip_value))
    print("Country:", attributes.get("country", "Not available"))
    print("Continent:", attributes.get("continent", "Not available"))
    print("ASN:", attributes.get("asn", "Not available"))
    print("AS owner:", attributes.get("as_owner", "Not available"))
    print("Network:", attributes.get("network", "Not available"))
    print(
        "Regional registry:",
        attributes.get(
            "regional_internet_registry",
            "Not available",
        ),
    )
    print("Reputation:", attributes.get("reputation", 0))
    print(
        "Last analysis:",
        format_timestamp(attributes.get("last_analysis_date")),
    )

    print_detection_summary(attributes, 2)

    print_section("3. HTTPS Certificate")

    certificate = attributes.get("last_https_certificate", {})
    subject = certificate.get("subject", {})
    issuer = certificate.get("issuer", {})

    print(
        "Certificate subject:",
        subject.get("CN", "Not available"),
    )
    print(
        "Certificate issuer:",
        issuer.get("CN", "Not available"),
    )

    print_section("4. Analyst Summary")

    stats = attributes.get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)

    if malicious > 0:
        print("Assessment: The IP address has malicious detections.")
        print("Recommended action: Block or investigate the IP address.")
    elif suspicious > 0:
        print("Assessment: The IP address has suspicious detections.")
        print("Recommended action: Investigate related traffic.")
    else:
        print("Assessment: No malicious detections were reported.")
        print(
            "Note: Shared hosting and cloud IP addresses may serve "
            "both legitimate and malicious systems."
        )


def validate_hash(file_hash):
    return (
        len(file_hash) in (32, 40, 64)
        and re.fullmatch(r"[A-Fa-f0-9]+", file_hash) is not None
    )


def extract_imports(attributes):
    pe_info = attributes.get("pe_info", {})
    import_list = pe_info.get("import_list", [])
    imports = []

    for library in import_list:
        library_name = library.get("library_name", "Unknown library")

        for function_name in library.get("imported_functions", []):
            imports.append((library_name, function_name))

    return imports


def analyze_suspicious_imports(imports):
    findings = []

    for library_name, function_name in imports:
        if function_name in SUSPICIOUS_IMPORTS:
            findings.append(
                f"{library_name}!{function_name} — "
                f"{SUSPICIOUS_IMPORTS[function_name]}"
            )

    return unique_items(findings)


def analyze_compilation(attributes):
    compiler_indicators = []
    metadata = attributes.get("packers", {})

    for tool_name, detected_value in metadata.items():
        detected_text = str(detected_value)

        if any(
            word in detected_text.lower()
            for word in COMPILER_WORDS
        ):
            compiler_indicators.append(
                f"{tool_name}: {detected_text}"
            )

    return unique_items(compiler_indicators)


def analyze_packing(attributes):
    indicators = []
    tags = attributes.get("tags", [])
    packers = attributes.get("packers", {})
    pe_info = attributes.get("pe_info", {})

    packing_words = (
        "packed",
        "packer",
        "upx",
        "obfuscated",
        "protector",
        "themida",
        "vmprotect",
        "aspack",
        "enigma",
    )

    for tag in tags:
        lowered_tag = str(tag).lower()

        if any(word in lowered_tag for word in packing_words):
            indicators.append(f"VirusTotal tag: {tag}")

    for tool_name, detected_value in packers.items():
        detected_text = str(detected_value)

        is_compiler = any(
            word in detected_text.lower()
            for word in COMPILER_WORDS
        )

        if not is_compiler:
            indicators.append(
                f"Possible packer signature: "
                f"{tool_name}: {detected_text}"
            )

    for section in pe_info.get("sections", []):
        entropy = section.get("entropy")
        section_name = section.get("name", "Unknown section")

        if isinstance(entropy, (int, float)) and entropy >= 7.2:
            indicators.append(
                f"High-entropy PE section: {section_name} "
                f"(entropy {entropy:.2f})"
            )

    return unique_items(indicators)


def get_relationship(sha256_hash, relationship):
    response = vt_get(
        f"/files/{sha256_hash}/{relationship}?limit={MAX_ITEMS}"
    )

    if response is None:
        return [], "Request failed"

    if response.status_code == 200:
        return response.json().get("data", []), None

    if response.status_code in (401, 403):
        return [], "Not available with this API account"

    if response.status_code == 404:
        return [], "No relationship data found"

    return [], f"VirusTotal returned status {response.status_code}"


def relationship_names(objects):
    values = []

    for item in objects:
        item_type = item.get("type")
        item_id = item.get("id", "Unknown")
        attributes = item.get("attributes", {})

        if item_type == "domain":
            values.append(item_id)
        elif item_type == "ip_address":
            values.append(item_id)
        elif item_type == "url":
            values.append(attributes.get("url", item_id))
        elif item_type == "file":
            name = attributes.get("meaningful_name", "Unknown name")
            sha256_hash = attributes.get("sha256", item_id)
            values.append(f"{name} — {sha256_hash}")
        else:
            values.append(item_id)

    return unique_items(values)


def get_behaviour_summary(sha256_hash):
    response = vt_get(
        f"/files/{sha256_hash}/behaviour_summary"
    )

    if response is None:
        return {}, "Request failed"

    if response.status_code == 200:
        return response.json().get("data", {}), None

    if response.status_code in (401, 403):
        return {}, "Behavior details are unavailable with this API account"

    if response.status_code == 404:
        return {}, "No sandbox behavior report is available"

    return {}, f"VirusTotal returned status {response.status_code}"


def get_mitre_attack_summary(sha256_hash):
    response = vt_get(
        f"/files/{sha256_hash}/behaviour_mitre_trees"
    )

    if response is None:
        return {}, "MITRE ATT&CK request failed"

    if response.status_code == 200:
        return response.json().get("data", {}), None

    if response.status_code in (401, 403):
        return {}, (
            "MITRE ATT&CK information is unavailable "
            "with this API account"
        )

    if response.status_code == 404:
        return {}, "No MITRE ATT&CK sandbox information is available"

    return {}, (
        f"VirusTotal returned status {response.status_code} "
        "for MITRE ATT&CK"
    )


def extract_mitre_techniques(mitre_data):
    techniques = []
    seen = set()

    for sandbox_name, sandbox_data in mitre_data.items():
        tactics = sandbox_data.get("tactics", [])

        for tactic in tactics:
            tactic_id = tactic.get("id", "Unknown tactic")
            tactic_name = tactic.get("name", "Unknown tactic")

            for technique in tactic.get("techniques", []):
                technique_id = technique.get(
                    "id",
                    "Unknown technique",
                )
                technique_name = technique.get(
                    "name",
                    "Unknown technique",
                )

                key = (technique_id, tactic_id)

                if key in seen:
                    continue

                seen.add(key)

                severities = {
                    signature.get("severity", "UNKNOWN")
                    for signature in technique.get(
                        "signatures",
                        [],
                    )
                }

                severity_text = ", ".join(
                    sorted(severities)
                )

                if not severity_text:
                    severity_text = "Not specified"

                techniques.append(
                    {
                        "technique_id": technique_id,
                        "technique_name": technique_name,
                        "tactic_id": tactic_id,
                        "tactic_name": tactic_name,
                        "sandbox": sandbox_name,
                        "severity": severity_text,
                    }
                )

    return techniques


def convert_values(values):
    results = []

    if not values:
        return results

    for value in values:
        if isinstance(value, str):
            results.append(value)
        elif isinstance(value, dict):
            readable = (
                value.get("hostname")
                or value.get("ip")
                or value.get("url")
                or value.get("path")
                or value.get("command")
                or value.get("name")
                or str(value)
            )
            results.append(str(readable))
        else:
            results.append(str(value))

    return unique_items(results)


def clean_network_values(values):
    return unique_items(
        value
        for value in values
        if ".in-addr.arpa" not in str(value).lower()
    )


def collect_file_relationships(sha256_hash):
    relationship_map = {
        "execution_parents": "Execution Parents",
        "bundled_files": "Bundled Files",
        "pe_resource_children": "PE Resource Children",
        "pe_resource_parents": "PE Resource Parents",
        "contacted_domains": "Contacted Domains",
        "contacted_ips": "Contacted IP Addresses",
        "contacted_urls": "Contacted URLs",
        "dropped_files": "Dropped Files",
    }

    results = {}
    errors = {}

    for relationship, display_name in relationship_map.items():
        objects, error = get_relationship(
            sha256_hash,
            relationship,
        )

        readable_values = relationship_names(objects)

        if relationship == "contacted_domains":
            readable_values = clean_network_values(
                readable_values
            )

        results[display_name] = readable_values

        if error:
            errors[display_name] = error

    return results, errors


def infer_possible_purpose(
    attributes,
    suspicious_imports,
    behaviour,
    network_indicators,
):
    evidence = []
    purposes = []

    tags = " ".join(
        str(tag).lower()
        for tag in attributes.get("tags", [])
    )

    vendor_results = attributes.get("last_analysis_results", {})

    detection_text = " ".join(
        str(result.get("result", "")).lower()
        for result in vendor_results.values()
        if result.get("result")
    )

    combined_text = f"{tags} {detection_text}"

    if any(word in combined_text for word in ("ransom", "ransomware")):
        purposes.append("Ransomware")
        evidence.append(
            "Antivirus detection names or VirusTotal tags reference ransomware"
        )

    if any(
        word in combined_text
        for word in ("stealer", "infostealer", "credential")
    ):
        purposes.append("Information or credential stealer")
        evidence.append(
            "Detection names or tags reference information theft"
        )

    if any(
        word in combined_text
        for word in ("downloader", "dropper", "loader")
    ):
        purposes.append("Downloader, loader, or dropper")
        evidence.append(
            "Detection names or tags reference file-loading behavior"
        )

    if any(
        word in combined_text
        for word in ("backdoor", "remote access", "trojan-rat")
    ):
        purposes.append("Backdoor or remote-access malware")
        evidence.append(
            "Detection names or tags reference remote-access behavior"
        )

    if any(
        "GetAsyncKeyState" in finding
        for finding in suspicious_imports
    ):
        purposes.append("Possible keyboard-monitoring capability")
        evidence.append(
            "The file imports the GetAsyncKeyState function"
        )

    if network_indicators:
        evidence.append("Network-related indicators were reported")

    if behaviour.get("files_written"):
        evidence.append(
            "Sandbox activity includes files written to disk"
        )

    if behaviour.get("command_executions"):
        evidence.append(
            "Sandbox activity includes command execution"
        )

    if behaviour.get("registry_keys_set"):
        evidence.append(
            "Sandbox activity includes Windows Registry modifications"
        )

    if not purposes:
        purposes.append(
            "Purpose could not be determined confidently"
        )

    return unique_items(purposes), unique_items(evidence)


def calculate_confidence(purposes, evidence, malicious_count):
    if (
        malicious_count >= 20
        and purposes
        and "could not be determined" not in purposes[0].lower()
        and len(evidence) >= 3
    ):
        return "HIGH"

    if malicious_count >= 5 and len(evidence) >= 1:
        return "MEDIUM"

    return "LOW"


def save_json_report(
    sha256_hash,
    report,
    behaviour,
    relationships,
    mitre_data,
):
    script_directory = Path(__file__).resolve().parent
    project_directory = script_directory.parent
    output_directory = project_directory / "sample-output"

    output_directory.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now(timezone.utc).strftime(
        "%Y%m%d_%H%M%S"
    )

    output_path = output_directory / (
        f"{sha256_hash}_{timestamp}_report.json"
    )

    export_data = {
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "file_report": report,
        "behaviour_summary": behaviour,
        "relationships": relationships,
        "mitre_attack": mitre_data,
    }

    try:
        with output_path.open("w", encoding="utf-8") as output_file:
            json.dump(
                export_data,
                output_file,
                indent=4,
                ensure_ascii=False,
            )

        return output_path, None

    except OSError as error:
        return None, str(error)


def analyze_file_hash(file_hash=None):
    if file_hash is None:
        file_hash = input(
            "Enter an MD5, SHA-1, or SHA-256 file hash: "
        ).strip()
    else:
        file_hash = str(file_hash).strip()

    if not validate_hash(file_hash):
        print(
            "Error: Enter a valid MD5, SHA-1, or SHA-256 hexadecimal hash."
        )
        return

    report = handle_response(
        vt_get(f"/files/{file_hash}")
    )

    if not report:
        return

    attributes = report["data"]["attributes"]

    sha256_hash = attributes.get("sha256", file_hash)
    stats = attributes.get("last_analysis_stats", {})
    vendor_results = attributes.get("last_analysis_results", {})
    pe_info = attributes.get("pe_info", {})

    imports = extract_imports(attributes)
    suspicious_imports = analyze_suspicious_imports(imports)
    compiler_indicators = analyze_compilation(attributes)
    packing_indicators = analyze_packing(attributes)

    behaviour, behaviour_error = get_behaviour_summary(
        sha256_hash
    )

    mitre_data, mitre_error = get_mitre_attack_summary(
        sha256_hash
    )

    mitre_techniques = extract_mitre_techniques(
        mitre_data
    )

    all_relationships, relationship_errors = (
        collect_file_relationships(sha256_hash)
    )

    print_header("VIRUSTOTAL MALWARE ANALYSIS REPORT")

    print_section("1. File Identity")
    print("Name:", attributes.get("meaningful_name", "Unknown"))
    print("Type:", attributes.get("type_description", "Unknown"))
    print("MD5:", attributes.get("md5", "Unknown"))
    print("SHA-1:", attributes.get("sha1", "Unknown"))
    print("SHA-256:", sha256_hash)
    print("File size:", attributes.get("size", "Unknown"), "bytes")
    print(
        "First submitted:",
        format_timestamp(attributes.get("first_submission_date")),
    )
    print(
        "Last analysis:",
        format_timestamp(attributes.get("last_analysis_date")),
    )

    print_section("2. Detection Summary")

    malicious_count = stats.get("malicious", 0)

    print("Total antivirus engines:", sum(stats.values()))
    print("Malicious:", malicious_count)
    print("Suspicious:", stats.get("suspicious", 0))
    print("Undetected:", stats.get("undetected", 0))
    print("Harmless:", stats.get("harmless", 0))

    print_section("3. Selected Vendor Detection Names")

    detections = []

    for vendor_name, vendor_data in vendor_results.items():
        if vendor_data.get("category") in ("malicious", "suspicious"):
            detection_name = (
                vendor_data.get("result")
                or "No detection name provided"
            )

            detections.append(
                f"{vendor_name}: {detection_name}"
            )

    print_list(
        detections,
        "No malicious vendor detections were reported.",
    )

    print_section("4. Compilation Information")
    print(
        "Compilation timestamp:",
        format_timestamp(pe_info.get("timestamp")),
    )
    print_list(
        compiler_indicators,
        "No compiler or build-tool information was identified.",
    )

    print_section("5. Packing or Obfuscation Indicators")

    if packing_indicators:
        print("Possible packing or obfuscation indicators were found:")
        print_list(packing_indicators)
        print(
            "\nImportant: These indicators do not prove that the file "
            "is malicious or packed."
        )
    else:
        print(
            "No clear packing or obfuscation indicators were found."
        )

    print_section("6. Suspicious or Notable Imports")
    print_list(
        suspicious_imports,
        "No notable imports were identified.",
    )

    print_section("7. Host-Based Indicators")

    if behaviour_error:
        print(behaviour_error)
    else:
        host_indicators = []

        field_labels = {
            "files_written": "File written",
            "files_deleted": "File deleted",
            "files_dropped": "File dropped",
            "registry_keys_set": "Registry key set",
            "registry_keys_deleted": "Registry key deleted",
            "mutexes_created": "Mutex created",
            "processes_created": "Process created",
            "command_executions": "Command executed",
            "services_created": "Service created",
        }

        for field_name, label in field_labels.items():
            for value in convert_values(
                behaviour.get(field_name, [])
            ):
                host_indicators.append(
                    f"{label}: {value}"
                )

        print_list(
            host_indicators,
            "No host-based indicators were available.",
        )

    print_section("8. Network-Based Indicators")

    network_indicators = []

    for value in clean_network_values(
        convert_values(behaviour.get("dns_lookups", []))
    ):
        network_indicators.append(f"DNS lookup: {value}")

    for value in clean_network_values(
        convert_values(behaviour.get("ip_traffic", []))
    ):
        network_indicators.append(f"IP traffic: {value}")

    for value in clean_network_values(
        convert_values(behaviour.get("http_conversations", []))
    ):
        network_indicators.append(f"HTTP conversation: {value}")

    print_list(
        network_indicators,
        "No meaningful network-based indicators were available.",
    )

    print_section("9. MITRE ATT&CK Mapping")

    if mitre_error:
        print(mitre_error)

    if mitre_techniques:
        for technique in mitre_techniques[:MAX_ITEMS]:
            print(
                f"- {technique['technique_id']} — "
                f"{technique['technique_name']}"
            )
            print(
                f"  Tactic: {technique['tactic_id']} — "
                f"{technique['tactic_name']}"
            )
            print(
                f"  Sandbox: {technique['sandbox']}"
            )
            print(
                f"  Severity: {technique['severity']}"
            )

        remaining = len(mitre_techniques) - MAX_ITEMS

        if remaining > 0:
            print(
                f"...and {remaining} additional MITRE ATT&CK mappings."
            )
    else:
        print(
            "No MITRE ATT&CK techniques were reported "
            "by the available VirusTotal sandboxes."
        )

    print(
        "\nAnalyst note: MITRE mappings should be validated "
        "before being treated as confirmed techniques."
    )

    print_section("10. VirusTotal Relationships")

    for relationship_name, values in all_relationships.items():
        print(f"\n{relationship_name}")
        print("-" * 72)

        print_list(
            values,
            f"No {relationship_name.lower()} were available.",
        )

        if relationship_name in relationship_errors:
            print(
                f"Note: {relationship_errors[relationship_name]}"
            )

    purposes, evidence = infer_possible_purpose(
        attributes,
        suspicious_imports,
        behaviour,
        network_indicators,
    )

    confidence = calculate_confidence(
        purposes,
        evidence,
        malicious_count,
    )

    print_section("11. Final Assessment")
    print("Likely malware purpose:")
    print_list(purposes)
    print(f"\nConfidence: {confidence}")

    print("\nSupporting evidence:")
    print_list(
        evidence,
        "Insufficient evidence was available.",
    )

    print("\nRecommended action:")

    if malicious_count > 0:
        print("- Do not execute the file on a production system.")
        print("- Analyze the sample only inside an isolated sandbox.")
        print("- Block confirmed malicious hashes and indicators.")
    else:
        print("- Continue investigation before deciding it is safe.")

    print(
        "\nAnalyst note: This assessment is an automated inference "
        "and should be verified with additional analysis."
    )

    output_path, export_error = save_json_report(
        sha256_hash,
        report,
        behaviour,
        all_relationships,
        {
            "raw": mitre_data,
            "techniques": mitre_techniques,
            "error": mitre_error,
        },
    )

    print_section("12. JSON Export")

    if export_error:
        print(f"The JSON report could not be saved: {export_error}")
    else:
        print("Full report saved successfully:")
        print(output_path)

    print("\nAnalysis complete.")



def calculate_file_hashes(file_path):
    """Calculate MD5, SHA-1, and SHA-256 without executing the file."""

    md5_hash = hashlib.md5()
    sha1_hash = hashlib.sha1()
    sha256_hash = hashlib.sha256()

    try:
        with file_path.open("rb") as input_file:
            while True:
                chunk = input_file.read(1024 * 1024)

                if not chunk:
                    break

                md5_hash.update(chunk)
                sha1_hash.update(chunk)
                sha256_hash.update(chunk)

    except OSError as error:
        return None, str(error)

    return {
        "md5": md5_hash.hexdigest(),
        "sha1": sha1_hash.hexdigest(),
        "sha256": sha256_hash.hexdigest(),
    }, None


def upload_file_to_virustotal(file_path):
    """Upload one file to the standard VirusTotal scanning endpoint."""

    headers = {
        "accept": "application/json",
        "x-apikey": API_KEY,
    }

    try:
        with file_path.open("rb") as input_file:
            files = {
                "file": (
                    file_path.name,
                    input_file,
                    "application/octet-stream",
                )
            }

            return requests.post(
                f"{BASE_URL}/files",
                headers=headers,
                files=files,
                timeout=180,
            )

    except OSError as error:
        print(f"Error opening the file: {error}")
        return None

    except requests.RequestException as error:
        print(f"Upload or API error: {error}")
        return None


def wait_for_analysis(analysis_id):
    """Poll VirusTotal until the submitted analysis completes or times out."""

    print("\nWaiting for VirusTotal analysis to complete...")

    for poll_number in range(1, ANALYSIS_MAX_POLLS + 1):
        response = vt_get(f"/analyses/{analysis_id}")

        if response is None:
            return False

        if response.status_code == 200:
            analysis = response.json()
            status = (
                analysis.get("data", {})
                .get("attributes", {})
                .get("status", "unknown")
            )

            print(
                f"Analysis check {poll_number}/{ANALYSIS_MAX_POLLS}: "
                f"{status}"
            )

            if status == "completed":
                return True

        elif response.status_code == 429:
            print(
                "VirusTotal rate limit reached while checking the analysis. "
                "Wait and try the file-hash option later."
            )
            return False

        else:
            print(
                "VirusTotal could not return the analysis status. "
                f"Status code: {response.status_code}"
            )
            return False

        if poll_number < ANALYSIS_MAX_POLLS:
            time.sleep(ANALYSIS_POLL_SECONDS)

    print(
        "\nThe analysis is still pending. The file was submitted successfully, "
        "but VirusTotal needs more time."
    )
    return False


def upload_and_analyze_file():
    """Hash-first lookup, then optionally upload a local file to VirusTotal."""

    print_header("UPLOAD AND ANALYZE A SUSPICIOUS FILE")

    entered_path = input(
        "Enter the complete path to the local file: "
    ).strip()

    if not entered_path:
        print("Error: A file path is required.")
        return

    file_path = Path(entered_path).expanduser()

    if not file_path.exists():
        print("Error: The specified file does not exist.")
        return

    if not file_path.is_file():
        print("Error: The specified path is not a regular file.")
        return

    try:
        file_size = file_path.stat().st_size
    except OSError as error:
        print(f"Error reading file information: {error}")
        return

    print("\nFile:", file_path)
    print("File size:", file_size, "bytes")

    hashes, hash_error = calculate_file_hashes(file_path)

    if hash_error:
        print(f"Could not calculate file hashes: {hash_error}")
        return

    print("MD5:", hashes["md5"])
    print("SHA-1:", hashes["sha1"])
    print("SHA-256:", hashes["sha256"])
    print("\nChecking whether VirusTotal already has this file...")

    existing_response = vt_get(f"/files/{hashes['sha256']}")

    if existing_response is None:
        return

    if existing_response.status_code == 200:
        print(
            "\nVirusTotal already has a report for this SHA-256. "
            "The file will not be uploaded again."
        )
        analyze_file_hash(hashes["sha256"])
        return

    if existing_response.status_code != 404:
        handle_response(existing_response)
        return

    if file_size > MAX_DIRECT_UPLOAD_BYTES:
        print("\nThis version supports direct uploads only up to 32 MB.")
        print(
            "The file was not uploaded. Larger uploads require VirusTotal's "
            "temporary upload-URL workflow."
        )
        return

    print("\n" + "!" * 72)
    print("PUBLIC VIRUSTOTAL UPLOAD WARNING".center(72))
    print("!" * 72)
    print("Uploading sends this file outside your Kali VM to VirusTotal.")
    print(
        "Standard VirusTotal uploads may be shared with VirusTotal's "
        "security community and partners."
    )
    print("\nDo not upload files containing:")
    print("- passwords, API keys, or credentials")
    print("- personal, medical, financial, or customer information")
    print("- confidential or proprietary company data")
    print("- material you do not own or lack permission to submit")
    print("- classified, regulated, or otherwise restricted information")
    print("\nThe file will be uploaded but will not be executed by this script.")

    confirmation = input(
        "\nType UPLOAD exactly to confirm, or press Enter to cancel: "
    ).strip()

    if confirmation != "UPLOAD":
        print("Upload cancelled. No file was sent.")
        return

    print("\nUploading file to VirusTotal...")
    upload_response = upload_file_to_virustotal(file_path)

    if upload_response is None:
        return

    print("Upload Status Code:", upload_response.status_code)

    if upload_response.status_code not in (200, 201):
        if upload_response.status_code == 401:
            print("Authentication failed. Check your API key.")
        elif upload_response.status_code == 403:
            print("Upload access was denied by VirusTotal.")
        elif upload_response.status_code == 413:
            print("VirusTotal rejected the file because it is too large.")
        elif upload_response.status_code == 429:
            print("VirusTotal API rate limit reached. Try again later.")
        else:
            print("VirusTotal rejected the upload:")
            print(upload_response.text)
        return

    try:
        upload_data = upload_response.json()
        analysis_id = upload_data["data"]["id"]
    except (ValueError, KeyError, TypeError):
        print(
            "The upload succeeded, but the analysis identifier "
            "could not be read."
        )
        return

    print("Analysis ID:", analysis_id)

    if wait_for_analysis(analysis_id):
        print("\nAnalysis completed. Retrieving the full file report...")
        analyze_file_hash(hashes["sha256"])
    else:
        print("\nYou can retrieve the report later using option 4:")
        print(hashes["sha256"])

def extract_ascii_strings(data):
    pattern = rb"[\x20-\x7e]{" + str(
        MINIMUM_STRING_LENGTH
    ).encode() + rb",}"

    return [
        match.decode("ascii", errors="replace")
        for match in re.findall(pattern, data)
    ]


def extract_unicode_strings(data):
    pattern = (
        rb"(?:[\x20-\x7e]\x00){"
        + str(MINIMUM_STRING_LENGTH).encode()
        + rb",}"
    )

    return [
        match.decode("utf-16le", errors="replace")
        for match in re.findall(pattern, data)
    ]


def analyze_strings():
    print_header("STATIC FILE STRINGS ANALYSIS")

    entered_path = input(
        "Enter the complete path to the local file: "
    ).strip()

    file_path = Path(entered_path).expanduser()

    if not file_path.exists():
        print("Error: The specified file does not exist.")
        return

    if not file_path.is_file():
        print("Error: The specified path is not a regular file.")
        return

    try:
        data = file_path.read_bytes()
    except OSError as error:
        print(f"Error reading the file: {error}")
        return

    strings = unique_items(
        extract_ascii_strings(data)
        + extract_unicode_strings(data)
    )

    print("File:", file_path)
    print("File size:", len(data), "bytes")
    print("Total unique strings:", len(strings))

    print_section("Selected Extracted Strings")

    print_list(
        strings,
        "No readable strings were found.",
        MAX_DISPLAYED_STRINGS,
    )

    output_directory = (
        Path(__file__).resolve().parent.parent
        / "sample-output"
    )

    output_directory.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now(timezone.utc).strftime(
        "%Y%m%d_%H%M%S"
    )

    output_path = output_directory / (
        f"{file_path.name}_{timestamp}_strings.txt"
    )

    try:
        with output_path.open(
            "w",
            encoding="utf-8",
            errors="replace",
        ) as output_file:
            for value in strings:
                output_file.write(value + "\n")

        print("\nFull strings report saved successfully:")
        print(output_path)
    except OSError as error:
        print(f"Could not save strings report: {error}")

    print(
        "\nSafety note: The file was read as raw data only. "
        "It was not executed."
    )


def display_menu():
    print_header("VIRUSTOTAL THREAT INTELLIGENCE TOOL")

    print("1. Analyze a URL")
    print("2. Analyze a domain")
    print("3. Analyze an IP address")
    print("4. Analyze a file hash")
    print("5. Extract strings from a local file")
    print("6. Upload and analyze a suspicious file")
    print("7. Exit")


def main():
    if not API_KEY:
        print("Error: VT_API_KEY was not found in the .env file.")
        raise SystemExit(1)

    while True:
        display_menu()

        choice = input("\nChoose an option: ").strip()

        if choice == "1":
            analyze_url()
        elif choice == "2":
            analyze_domain()
        elif choice == "3":
            analyze_ip()
        elif choice == "4":
            analyze_file_hash()
        elif choice == "5":
            analyze_strings()
        elif choice == "6":
            upload_and_analyze_file()
        elif choice == "7":
            print("\nExiting the threat-intelligence tool.")
            break
        else:
            print(
                "\nInvalid selection. "
                "Choose 1, 2, 3, 4, 5, 6, or 7."
            )

        input("\nPress Enter to return to the main menu...")


if __name__ == "__main__":
    main()
