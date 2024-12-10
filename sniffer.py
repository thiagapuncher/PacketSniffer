import sys
from scapy.all import *

# this handles each packet
def handle_packet(packet, log):
    # check if the packet has a TCP layer
    if packet.haslayer(TCP):
        # get the source and destination IP address
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        # get the source and destination ports
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        # write the packet information to the log file
        log.write(f"Packet: {src_ip}:{src_port} -> {dst_ip}:{dst_port}\n")

# starts packet sniffing
def main(interface, verbose=False):
    # create a log file name based on the interface
    logfilename = f"sniffer_{interface}_log.txt"
    # open the log file
    with open(logfilename, "w") as logfile:
        try:
            # start sniffing packets
            sniff_params = {
                'iface': interface,
                'prn': lambda pkt: handle_packet(pkt, logfile),
                'store': 0
            }
            # only add verbose param if True, to avoid potential issues
            if verbose:
                sniff_params['verbose'] = True

            sniff(**sniff_params)

        except KeyboardInterrupt:
            sys.exit(0)

if __name__ == "__main__":
    # check if the correct number of arguments are passed
    if len(sys.argv) < 2 or len(sys.argv) > 3:
        print("Usage: python sniffer.py <interface> [verbose]")
        sys.exit(1)

    verbose = False
    if len(sys.argv) == 3 and sys.argv[2].lower() == "verbose":
        verbose = True

    main(sys.argv[1], verbose)
