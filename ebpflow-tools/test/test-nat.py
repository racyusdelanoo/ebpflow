#!/usr/bin/env python3
from scapy.all import *
import sys
from subprocess import check_output
import re

def main(argv):
    inpcap = ""
    if len(argv) < 2:
        print("Expected pcap input file")
        return -1

    inpcap = argv[1]
    reply = "/tmp/" + inpcap.split(".")[-2] + "-reply.pcap"
    outbound = "/tmp/nat-outbound.pcap"
    inbound = "/tmp/nat-inbound.pcap"
    nat_obj = "../examples/nat.o"
    rules = "/tmp/test-nat.rules"

    output = check_output("../tools/ebpflow-test -a -b -p 0 -o {} -f {} {}".format(outbound,inpcap,nat_obj).split(" "))
    output = output.decode("utf-8")

    # print("========= Outbound packets =========")
    # print(output)

    map_entries = {}

    # Parse NAT entries
    for idx,line in enumerate(output.split("\n")):
        # print(line)
        if re.match(".0x[0-9a-fA-F]+.0x[0-9a-fA-F]+", line):
            vals = re.sub("\t"," ",line.strip()).split()
            map_entries[vals[0]] = vals[1]

    # Save NAT entries to temp rules file
    with open(rules,"w") as frules:
        frules.write("# NAT entries\n")
        for k,v in map_entries.items():
            frules.write("mappings {} {}\n".format(k,v))

    # Swap dst and src to simulate reply
    with PcapWriter(reply) as pw:
        for pkt in PcapReader(outbound):
            pkt[IP].src, pkt[IP].dst = pkt[IP].dst, pkt[IP].src
            proto = int(pkt[IP].proto)

            if proto == 6: # TCP
                pkt[TCP].sport, pkt[TCP].dport = pkt[TCP].dport, pkt[TCP].sport
            elif proto == 17: # UDP
                pkt[UDP].sport, pkt[UDP].dport = pkt[UDP].dport, pkt[UDP].sport

            pw.write(pkt)

    output = check_output("../tools/ebpflow-test -a -b -r {} -p 1 -o {} -f {} {}".format(rules,inbound,reply,nat_obj).split(" "))

    # Compare src and reply
    reqs = PcapReader(inpcap)
    reps = PcapReader(inbound)

    cnt = 1
    failcnt = 0

    for req,reply in zip(reqs,reps):
        failed = False
        # print("[Packet #{}]".format(cnt))

        if req[IP].src != reply[IP].dst or req[IP].dst != reply[IP].src:
            # print("IPs don't match")
            failed = True

        if req.haslayer(TCP):
            if req[TCP].sport != reply[TCP].dport or req[TCP].dport != reply[TCP].sport:
                # print("TCP ports don't match")
                failed = True

        if req.haslayer(UDP):
            if req[UDP].sport != reply[UDP].dport or req[UDP].dport != reply[UDP].sport:
                # print("TCP ports don't match")
                failed = True

        if failed:
            failcnt = failcnt + 1

        cnt = cnt + 1

    print("{0} ({1:.3f}%) packets failed".format(failcnt,failcnt/cnt))
    # print("========= Inbound packets =========")
    # print(output.decode("utf-8"))


if __name__ == "__main__":
    main(sys.argv)