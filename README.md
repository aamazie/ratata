# ratata
UEFI-encoded RAT attack tester suite for headers injections on servers.

Ratata takes in an IP, an IPv4, which you can modify in the list in the python file, and attacks it with obsfuscated RAT payloads.. these payloads are obsfuscated in different ways in each version, v1.0 and v2.0 using a UEFI encoder and v3.0 using a polyglot encoder. Right now the file targets the evil master of all servers on chuckecheese.com. You can add as many as you want but when you run the script it asks how many iterations you want.. default is 100, which is a lot (set at 2 is recommended..).. these iterations test RAT debug payloads that are in the code.

ratata_v2 (the version 2.0) is what you want . the first iteration it does is a standard, well-tested well-battled polyglot that works on a lot of stuff...
i call it the ratata polyglot and it's now available in ratata 2.0.

ratata_v3 is even better though.. it uses a recursive ai to add to the ratata polyglot in 2.0. each iteration builds upon the ratata polyglot to achieve an execution.

ratata 1.0 is pure UEFI rando algo stuff.. try to get something new.

to install do:

git clone https://github.com/aamazie/ratata/

to run do:

cd ratata

python ratata_v2.py


ALSO included a UEFI injection debug scanner. Injects a NOP sled + overflow + INT3 trap (for debug). Shows up if the maxheaders go above 256-bit and cause a header buffer overflow.


DISCLAIMER: the developers claim no responsibility or liability for the public misuse of this debugger, their property.

Don't run raticate.
