# Urgent11-Suricata-LUA-scripts
Suricata LUA scripts to detect CVE-2019-12255, CVE-2019-12256, CVE-2019-12258, and CVE-2019-12260

## CVE-2019-12255
The script checks for CVE-2019-12255, the packet that is checked needs to have the PSH, ACK, and URG flags set, and have a payload size that exceeds 1500 bytes. It then checks if the value of the urgent pointer is set to 0, this will cause an integer underflow on vulnerable devices.

The exploit is based on underflowing the urgent pointer by setting it to 0. The flaw causes the length constraint in the recv() of the target to be ignored, and will copy all of the available data from the TCP window to the user supplied buffer. The rule checks if the payload exceeds 1500 bytes.

## CVE-2019-12256
The script checks for CVE-2019-12256, the packet that is checked consists of two LSRR or SSRR options in the IP packet. The LSRR options can be recognized with hex value 0x83, the SSRR option with hex value 0x89, the exploit gives consists of invalid values, the length is less than the length normally used when defining a route (4 bytes minimum), this is present twice in the packet that is sent to the server. The following IP options will trigger a stack overflow with invalid LSRR options:

| Type LSRR | Length | LSRR-Pointer | Type LSRR | Length | LSRR-Pointer |
|-----------|--------|--------------|-----------|--------|--------------|
| \x83      | \x03   | \x27         | \x83      | \x03   | \x27

The following IP options will trigger a stack overflow with invalid SSRR options:

| Type SSRR | Length | SSRR-Pointer | Type SSRR | Length | SSRR-Pointer |
|-----------|--------|--------------|-----------|--------|--------------|
| \x89      | \x03   | \x27         | \x89      | \x03   | \x27

## CVE-2019-12258
The script checks for CVE-2019-12258, the packets involved are marked with a comment in the PCAP. The first detection is being checked given 2 window scale options, 1 invalid and 1 valid. The second time it is the unweaponized DoS variant which holds 1 invalid window scale option.

The Window Scale option has value 03 to indicate this option is being used, this is on a set  offset of 57 in the TCP packet. The exploit has to be of value 2 (invalid) for this exploit to trigger, this valueis located at offset 58. The values are being checked, returning 1 (match) if this is the case.

## CVE-2019-12260
The script checks for CVE-2019-12260, the packet that is checked consists of a malformed SYN packet, this packet contains a TCP-AO option field with a byte value of <= 3 bytes. The TCP-AO option can be set with hex value 0x29, as per RFC: https://tools.ietf.org/html/rfc5925#page-7

The exploit is based on malforming the TCP-AO option by setting it to anything that is less than or equal to 3 bytes. This can be checked by verifying that hex value 0x29 is set as an option at offset 56.
