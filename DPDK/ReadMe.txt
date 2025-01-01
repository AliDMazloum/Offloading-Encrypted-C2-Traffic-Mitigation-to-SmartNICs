This DPDK application is used to extend the capabilities of the P4 switch in parsing TLS variable length headers. 

It has the following components:
    1) The main.c file. This is the source code of the DPDK application. It reads the regex rules from: "/home/ubuntu/rof/.rof2.binary". More information about the process of generating the rules file is located at the Commands.txt file
    2) The generate_random_strings.py is a python script responsible for generating random strings that are used by the regex compiler to create the matching rules.
