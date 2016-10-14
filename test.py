import logging
import struct
import time
import calendar
from random import randint
import argparse
from logging.handlers import TimedRotatingFileHandler

import trafficmodel

OUTPUT_FILE = 'sample_data/test.pcap'
START_TIME = 'Sun Oct 2 00:00:00 2016'
INTERNAL_HOSTS = []
EXTERNAL_HOSTS = []

'''
we could have it seeded with X number of "internal" machines and Y number of
"external" machines. Then, upon boot, it could generate X and Y pairs of IP and
MAC addresses that are then used throughout the packet generations

Further, you could stipulate the netmask for the internal traffic so that you
could subsequently filter/whatever on that (e.g. 10.10.2.x)
'''

def get_random_mac():
    """
    Note: we could have simply done a big ole random number like this:
    return randint(0,0xffffffffffff)
    however we couldn't guarantee that we would achive the 6 full bytes we need.
    Therefore, we elected to build it manually using the struct function  
    """
    return struct.pack('BBBBBB',
                      randint(0,255),
                      randint(0,255),
                      randint(0,255),
                      randint(0,255),
                      randint(0,255),
                      randint(0,255))


def get_random_ip(first=0,second=0,third=0,fourth=0):
    if not first > 0:
        first = randint(1,255)
    if not second > 0:
        second = randint(0,255)
    if not third > 0:
        third = randint(0,255)
    if not fourth > 0:
        fourth = randint(0,255)

    return (first << 24) | (second << 16) | (third << 8) | fourth


def initialize_hosts(internal_count=50, external_count=500):
    logging.info("Creating {} internal hosts".format(internal_count))
    logging.info("Creating {} external hosts".format(external_count))
    global INTERNAL_HOSTS
    global EXTERNAL_HOSTS

    for i in range(0, internal_count-1):
        mac = get_random_mac()
        ip = get_random_ip(first=192, second=168)

        host = {
            "mac" : mac,
            "ip" : ip    
        }
        INTERNAL_HOSTS.append(host)

    for i in range(0, external_count-1):
        mac = get_random_mac()
        ip = get_random_ip()

        host = {
            "mac" : mac,
            "ip" : ip    
        }
        EXTERNAL_HOSTS.append(host)


# Notes:

# I == uint32 (int)
# i == int32 (int)
# H == uint16 (short)
# B == uint8 (char)

def create_global_header():
    return struct.pack('IHHiIII',
        0xa1b2c3d4,         # pcap magic number
        2,                  # major version number
        4,                  # minor version number
        0,                  # GMT to local correction
        0,                  # accuracy of timestamps,
        65535,              # max length of captured packets, in octets (snaplength!)
        1                   # data link type
    )

def get_start_time():
    start = time.strptime(START_TIME)
    return time.mktime(start)

def create_packet_header(start_time=get_start_time(), offset_ms=0, included_length=62, original_length=62):
    """
    ts_sec: the date and time when this packet was captured. This value is in seconds since January 1, 1970 00:00:00 GMT; this is also known as a UN*X time_t. You can use the ANSI C time() function from time.h to get this value, but you might use a more optimized way to get this timestamp value. If this timestamp isn't based on GMT (UTC), use thiszone from the global header for adjustments.
    ts_usec: in regular pcap files, the microseconds when this packet was captured, as an offset to ts_sec. In nanosecond-resolution files, this is, instead, the nanoseconds when the packet was captured, as an offset to ts_sec /!\ Beware: this value shouldn't reach 1 second (in regular pcap files 1 000 000; in nanosecond-resolution files, 1 000 000 000); in this case ts_sec must be increased instead!
    incl_len: the number of bytes of packet data actually captured and saved in the file. This value should never become larger than orig_len or the snaplen value of the global header.
    orig_len: the length of the packet as it appeared on the network when it was captured. If incl_len and orig_len differ, the actually saved packet size was limited by snaplen.
    """
    return struct.pack('IIII',
                       start_time,      # timestamp seconds
                       offset_ms,       # timestamp microseconds
                       included_length, # number of octets of packet saved in file (Included Bytes)
                       original_length  # actual length of packet (Original Bytes)
                      )


def build_ethernet_frame(internal_as_source, source_ndx, destination_ndx, link_type=0x0008):
    if internal_as_source:
        destination_mac =  EXTERNAL_HOSTS[destination_ndx]['mac']
        source_mac =  INTERNAL_HOSTS[source_ndx]['mac']
    else:
        destination_mac =  INTERNAL_HOSTS[destination_ndx]['mac']
        source_mac =  EXTERNAL_HOSTS[source_ndx]['mac']

    link_type_struct = struct.pack('H', link_type)

    return b"".join([destination_mac, source_mac, link_type_struct])

def build_ipv4_datagram(internal_as_source, source_ndx, destination_ndx):
    if internal_as_source:
        dest_ip =  EXTERNAL_HOSTS[destination_ndx]['ip']
        source_ip =  INTERNAL_HOSTS[source_ndx]['ip']
    else:
        dest_ip =  INTERNAL_HOSTS[destination_ndx]['ip']
        source_ip =  EXTERNAL_HOSTS[source_ndx]['ip']

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

    return struct.pack('!BBHHHBBHII',
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


def build_tcp_segment():
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

    return struct.pack('!HHIIBBHHHQ',
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


def create_packet(start_time=get_start_time(), offset_ms=0):

    # build the PCAP file packet header
    packet_header = create_packet_header(start_time=start_time, offset_ms = offset_ms)

    # randomly pick source and destination
    internal_as_source = randint(0,1)
    if internal_as_source:
        source_ndx = randint(0,len(INTERNAL_HOSTS) - 1)      
        destination_ndx = randint(0,len(EXTERNAL_HOSTS) - 1)
    else:
        source_ndx = randint(0,len(EXTERNAL_HOSTS) - 1)      
        destination_ndx = randint(0,len(INTERNAL_HOSTS) - 1)
    
    # build the ethernet frame (L2)
    ethernet_frame = build_ethernet_frame(internal_as_source, source_ndx, destination_ndx)
    
    # build the ipv4 datagram (L3)
    ipv4_datagram = build_ipv4_datagram(internal_as_source, source_ndx, destination_ndx)

    # build the tcp_segment (L4)
    tcp_segment = build_tcp_segment()

    # join and return the file
    return b"".join([packet_header, ethernet_frame, ipv4_datagram, tcp_segment])


def write_pcap(bytes_data, file_name=OUTPUT_FILE):
    with open(file_name, 'wb') as pcap_file:
        pcap_file.write(bytes_data)


# set max size to 300M (or 300,000,00)
def create_pcap_file(start_time=get_start_time(), duration=90, 
                     max_size=300000000, file_name=OUTPUT_FILE):
    logging.info("Creating a {0} second file named {1}".format(duration, file_name))
    file_data = []

    # calculate total # of packets
    size_file_header = 24
    size_packet_plus_header = 78
    num_packets = (max_size - size_file_header)/size_packet_plus_header

    # initialize the offsets
    start = int(start_time)
    # subtracting one from the end is important to ensure the random slide of
    # the offset doesn't put us over the time boundary
    end = int(start + duration) -1
    offset = 0

    global_header = create_global_header()
    file_data.append(global_header)

    for i in range(0, num_packets-1):
        if i % 100000 == 0:
            logging.info("Creating Packet: {0}".format(i))

        packet_data = create_packet(start, offset)
        file_data.append(packet_data)

        # set up the counters for the next loop
        # start by calculating the straight-line average inter-packet time given
        # the remaining packets and remaining time
        inter_packet_timing = int(((end-start) / float(num_packets-i))*1000000)

        # pick a random time b/t 0 and the straight-line value
        offset += randint(0, inter_packet_timing)

        # offset can't be greater than 1million as that would be another second
        # if this is the case, increase the start time and decrease the offset
        if offset >= 1000000:
            start += 1
            offset -= 1000000

    write_pcap(b"".join(file_data), file_name = file_name)


def main():
    # setup the argument parser
    parser = argparse.ArgumentParser(prog = 'python test.py',
                                     description = __doc__)

    parser.add_argument("--internal-hosts",
        help="Total number of internal hosts. (default: %(default)s)",
        default=50)

    parser.add_argument("--external-hosts",
        help="Total number of external hosts. (default: %(default)s)",
        default=500)

    parser.add_argument("--min-duration",
        help="Minimum duration of capture files. (default: %(default)s)",
        default=60)

    parser.add_argument("--max-duration",
        help="Maximum duration of capture files. (default: %(default)s)",
        default=120)

    parser.add_argument("--file-count",
        help="Number of files to generate. (default: %(default)s)",
        default=1)


    parser.add_argument("--log_file", 
        help="The path to the log file for the service. (default: %(default)s)",
        default='samples.log')

    # handle the logging levels
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--log-critical", action="store_const", dest='log_level', 
                       const=50, help='Log only the most critical errors')
    group.add_argument("--log-error", action="store_const", dest='log_level', 
                       const=40, help='Log all errors')
    group.add_argument("--log-warning", action="store_const", dest='log_level', 
                       const=30, help='Log warnings and above')
    group.add_argument("--log-info", action="store_const", dest='log_level', 
                       const=20, help='Log information and above (default)')
    group.add_argument("--log-debug", action="store_const", dest='log_level', 
                       const=10, 
                       help='Log debug information and above (verbose)')

    args = parser.parse_args()

    # setup the default... couldn't figure out how to do this better 
    # (must be a way...)
    if args.log_level is None:
        args.log_level = 20

    # setup logging
    logging.basicConfig(format='[%(asctime)s] %(message)s', level=args.log_level)

    handler = TimedRotatingFileHandler(args.log_file,
                                    when="d",
                                    interval=1,
                                    backupCount=20)
    fmt = logging.Formatter(fmt='[%(asctime)s] %(message)s')
    handler.setFormatter(fmt)
    logging.getLogger('').addHandler(handler)

    logging.info("Starting the ORCA Synthetic PCAP Generator Utility")

    # set up our random hosts
    initialize_hosts(internal_count=int(args.internal_hosts), 
                     external_count=int(args.external_hosts))

    start_time=get_start_time()

    if int(args.file_count) == 1:
        file_name = 'generated_0000.pcap'
        duration = randint(int(args.min_duration), int(args.max_duration))

        create_pcap_file(start_time=start_time, 
                         duration=duration, 
                         file_name=file_name)
    else:
        for i in range(0, int(args.file_count)):
            file_name = 'generated_{0:06d}.pcap'.format(i)

            # get a random number
            duration = randint(int(args.min_duration), int(args.max_duration))


            # use the model to generate
            next_time = time.localtime(start_time)

            # get is weekend (Mon = 0, Sun = 6)
            is_weekend = next_time.tm_wday > 4

            # get float of hour (military time)
            decimal_hour = next_time.tm_hour
            mins = next_time.tm_min + (next_time.tm_sec / float(60))
            decimal_hour += mins/60

            # get result, round, and convert to int
            duration = trafficmodel.get_duration_scalar(decimal_hour, is_weekend)
            duration = int(round(duration*480))
            logging.info("{0} - {1} - {2} - {3}".format(
                time.strftime("%a, %d %b %Y %H:%M:%S", next_time), 
                duration, decimal_hour, is_weekend))

            create_pcap_file(start_time=start_time, 
                            duration=duration, 
                            file_name=file_name)
            
            # set the start time for the next iteration
            start_time = start_time + duration


if __name__ == "__main__":
    main()
