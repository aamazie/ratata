# ratata
UEFI-encoded RAT attack scanner for headers injections on servers.

Ratata takes in an IP, an Ipv4, which you can modify in the list in the python file. Right now the file targets the evil master of all servers on chuckecheese.com. You can add as many as you want but when you run the script it asks how many iterations you want.. default is 100, which is a lot (set at 2 is recommended..).. these iterations test RAT debug payloads that are in the code.

ratata_v2 (the version 2.0) is what you want . the first iteration it does is a standard, well-tested well-battled polyglot that works on a lot of stuff...
i call it the ratata polyglot and it's only available in ratata 2.0.

ratata_v3 is even better though.. it uses a recursive ai to add to the ratata polyglot in 2.0. each iteration builds upon the ratata polyglot to achieve an execution.

ratata 1.0 is pure UEFI rando algo stuff.. try to get something new.

to install do:

git clone https://github.com/aamazie/ratata/

to run do:

cd ratata

python ratata_v2.py
