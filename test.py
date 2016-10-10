import logging
from struct import *

OUTPUT_FILE = 'sample_data/test.pcap'

def write_pcap(bytes_data):
    with open(OUTPUT_FILE, 'wb') as pcap_file:
        pcap_file.write(bytes_data)

# Notes:

# I == uint32 (int)
# i == int32 (int)
# H == uint16 (short)
# B == uint8 (char)

def create_global_header():
    return pack('IHHiIII',
        0xa1b2c3d4,         # pcap magic number
        2,                  # major version number
        4,                  # minor version number
        0,                  # GMT to local correction
        0,                  # accuracy of timestamps,
        65535,              # max length of captured packets, in octets (snaplength!)
        1                   # data link type
    )

def create_packet():
    packet_header = pack('IIII',
                         0x40a34b23,         # timestamp seconds
                         0x0004bfb8,         # timestamp microseconds
                         62,                 # number of octets of packet saved in file (Included Bytes)
                         62                  # actual length of packet (Original Bytes)
                        )
    
    #print "CRC Checksum:    " + str(self.crc)
    ethernet_frame = pack('BBBBBBBBBBBBH',
                          0xfe,             # destination mac address
                          0xff,
                          0x20,
                          0x00,
                          0x01,
                          0x00,
                          0x00,             # source mac address
                          0x00,
                          0x01,
                          0x00,
                          0x00,
                          0x00,
                          0x0008            # Type/Length (IP)
                         )
    
    # set up sub-byte values
    version = 4         # IP v4 (version) 0100....
    header_length = 5   # IHL/Internet Header Length... number of 32-bit words in header
                        # wireshark shows this in bytes (e.g. 5*32=160 bits/8 = 20 bytes)
                        # ....0101
    v1 = (version << 4) | header_length

    differentiated_services = 0             # 0000 00..
    explicit_congestion_notification = 0    # .... ..00
    v2 = (differentiated_services << 2) | explicit_congestion_notification

    # set up flags:
    reserved = 0                            # 0... .... .... ....
    dont_fragment = 1                       # .1.. .... .... ....
    more_fragments = 0                      # ..0. .... .... ....
    frament_offset = 0                      # ...0 0000 0000 0000
    v3 = (reserved << 15) | (dont_fragment << 14) | (more_fragments << 13) | frament_offset

    source_ip = (145 << 24) | (254 << 16) | (160 << 8) | 237
    dest_ip = (65 << 24) | (208 << 16) | (228 << 8) | 223

    ipv4_datagram = pack('!BBHHHBBHII',
                         v1,                # version | IHL
                         v2,                # DSCP | ECN
                         48,                # total length
                         0x0f41,            # identification (3905)
                         v3,                # flags | Fragment offset
                         128,               # Time to Live
                         6,                 # Protocol (TCP)
                         0x91eb,            # header checksum
                         source_ip,         # source_ip
                         dest_ip            # dest_ip
                        )

    data_offset = 7     # size of TCP header in 32-bit words 0000 ....
    tcp_reserved = 0    # reserved bit .... 000.
    flag_nonce = 0
    flag_cwr = 0        # congestion window reduced
    flag_ecn_echo = 0   # ECN-Echo
    flag_urgent = 0     # Urgent
    flag_ack = 0        # Acknowledgement
    flag_push = 0       # Push
    flag_reset = 0      # Reset
    flag_syn = 1        # Syn/Synchronize sequence numbers
    flag_fin = 0        # no more data from sender
    v4 = (data_offset << 4) | (tcp_reserved << 1) | flag_nonce
    v5 = (flag_cwr << 7) | (flag_ecn_echo << 6) | (flag_urgent << 5) | (flag_ack << 4) | (flag_push << 3) | (flag_reset << 2) | (flag_syn << 1) | flag_fin

    tcp_segment = pack('!HHIIBBHHHQ',
                        3372,               # source port
                        80,                 # destination port
                        0x38affe13,         # sequence number (wireshark will treat this relative and make first as 0)
                        0,                  # acknowledgement number
                        v4,                 # data offset | tcp_reserved | NS
                        v5,                 # cwr | ece | urg | ack | psh | rst | syn | fin
                        8760,               # window size
                        0xc30c,             # Checksum
                        0,                  # urgent pointer
                        0x020405b401010402  # option flags
                       )

        #print "\t Options Length: " + str(self.options_length)
    mock_data = pack('QQ',
                    0xffffffffffffffff,
                    0xffffffffffffffff)

    

    return b"".join([packet_header, ethernet_frame, ipv4_datagram, tcp_segment, mock_data])


def main():
    global_header = create_global_header()
    packet_data = create_packet()
    write_pcap(b"".join([global_header, packet_data]))

if __name__ == "__main__":
    main()
