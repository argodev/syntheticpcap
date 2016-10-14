# Synthetic PCAP Generator
Simple tool to generate synthetic PCAP data for testing purposes


In its current incarnation, this tool doesn't generate particularly interesting
packets/traffic, but it does allow you to generated a reasonably high volume 
of packets in case you are trying to load/stress test your abiity to handle
packet volume/parsing rates.

It generates completely random MAC addresses and IP addresses. Any similarities
between the addresses generated and real-life are completely conincidental.


## pcap anonymizer

Reads in a pcap and produces a new pcap with similar properties execpt that:
- MAC addresses have been randomized
- IP addresses have been randomized
- All data in requests (L5+) is randomized
- Optionally shift date/timestamps

