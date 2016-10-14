import logging
from logging.handlers import TimedRotatingFileHandler
import struct
from collections import namedtuple

TEST_FILE = 'sample_data/http.pcap'
TEST_OUT = 'sample_data/http_anon.pcap'
PcapHeader = namedtuple('PcapHeader', 'number major_version minor_version gmt_corr acc_timestamp max_length, data_link')
PacketHeader = namedtuple('PacketHeader', 'start_time offset_ms included_length original_length')
EthernetFrame = namedtuple('EthernetFrame', 'destination_mac source_mac ether_type')
MacAddress = namedtuple('MacAddress', 'a b c d e f')
Ipv4Datagram = namedtuple('Ipv4Datagram', 'version ihl dscp ecn total_length identification flags frament_offset time_to_live protocol header_checksum source_ip destination_ip options')


# Version	IHL	DSCP	ECN	Total Length
# 4	32	Identification	Flags	Fragment Offset
# 8	64	Time To Live	Protocol	Header Checksum
# 12	96	Source IP Address
# 16	128	Destination IP Address
# 20	160	Options (if IHL > 5)
pkt_count = 0



def read_file_header(byte_data):
    return PcapHeader._make(struct.unpack('IHHiIII', byte_data))


def read_packet_header(byte_data):
    return PacketHeader._make(struct.unpack('IIII', byte_data))


def read_ethernet_frame(byte_data):
    destination = MacAddress._make(struct.unpack('BBBBBB', byte_data[0:6]))
    source = MacAddress._make(struct.unpack('BBBBBB', byte_data[6:12]))
    ether_type = struct.unpack('H', byte_data[12:14])
    return EthernetFrame(destination_mac=destination, source_mac=source, ether_type=ether_type)

def read_ipv4_datagram(byte_data):
    pass


def clone_pcap_file(input_file, output_file):
    global pkt_count

    # open the file for reading (r) in binary (b) mode
    with open(input_file, "rb") as f:
        pcap_header = read_file_header(f.read(24))

        # attempt to read a packet
        packet_header_bytes = f.read(16)

        while (packet_header_bytes != "") and (len(packet_header_bytes) > 0):
            pkt_count += 1
            packet_header = read_packet_header(packet_header_bytes)            
            print(packet_header)

            packet_data_bytes = f.read(packet_header.included_length)            
            ethernet_frame = read_ethernet_frame(packet_data_bytes)
            print(ethernet_frame)



            # get the header for the next packet
            packet_header_bytes = f.read(16)
            

    logging.info("Finsished reading {0} packets".format(pkt_count))

def main():

    # setup logging
    logging.basicConfig(format='[%(asctime)s] %(message)s', level=logging.INFO)
    logging.info("Starting the ORCA Synthetic PCAP Anonymizer Utility")

    clone_pcap_file(TEST_FILE, TEST_OUT)

    # with open(TEST_FILE, "rb") as f:
        
    #     while packet_header_bytes != "":

    #         # read and drop the packet data bytes
    #         packet_data_bytes = f.read(packet_header.incl_len)

    #         layer_two = parse_layer_two(packet_data_bytes, header.little_endian)
    #         layer_three = parse_layer_three(layer_two.data)
    #         layer_four = parse_layer_four(layer_three.data)

    #         # get the header for the next packet
    #         packet_header_bytes = f.read(16)
    #         break


if __name__ == "__main__":
    main()
