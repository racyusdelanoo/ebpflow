#!/usr/bin/env python3

from scapy.all import *
import random
import argparse
import sys

def main(argv):
  parser = argparse.ArgumentParser(prog=argv[0],
    description='Generates a PCAP file with random header data based on an smaller base PCAP')

  parser.add_argument('-n', '--npackets', metavar='<number-of-pkts>', type=int,
    help='Number of packets in the output PCAP file', required=True, dest="npackets")

  parser.add_argument('-f', '--file', metavar='<input-pcap>',
    help='Input base PCAP file', required=True, dest="input")

  parser.add_argument('-o', '--output', metavar='<output-pcap>',
    help='Output PCAP file name', required=True, dest="output")

  args = vars(parser.parse_args())

  n = args['npackets']
  inpcap = args['input']
  outpcap = args['output']

  with PcapWriter(outpcap) as out:
    for pkt in PcapReader(inpcap):
      for i in range(0,n):
        pkt[IP].src = random.randint(0,0xFFFFFFFF)
        pkt[IP].dst = random.randint(0,0xFFFFFFFF)
        sport = random.randint(0,0xFFFF)
        dport = random.randint(0,0xFFFF)
        proto = int(pkt[IP].proto)
        if proto == 6:
          pkt[TCP].sport = sport
          pkt[TCP].dport = dport
        elif proto == 17:
          pkt[UDP].sport = sport
          pkt[UDP].dport = dport
        out.write(pkt)

if __name__ == "__main__":
  main(sys.argv)