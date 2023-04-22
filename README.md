# eBPFlow: a Hardware/Software Platform to Seamlessly Offload Network Functions Leveraging eBPF

eBPFlow is a platform that supports offloading NFs using the standard, general-purpose eBPF (extended Berkeley Packet Filter) instruction set already used widely in the Linux kernel. eBPF specifies a bytecode machine and an instruction set that we leverage to program general-purpose NFs on the data plane. eBPFlow is a platform for seamlessly accelerating network computation to deploy building upon eBPF. Moreover, it combines flexibility and programmability in software with high performance in hardware using an FPGA (Field Programmable Gate Array).

## About 
This repository presents complimentary material to the paper "eBPFlow: a Hardware/Software Platform to Seamlessly Offload Network Functions Levera    ging eBPF" submitted to IEEE/ACM Transactions on Networking (ToN).

The contents are divided as as follows:
- `bitstream/`:  File to load on NetFPGA SUME
- `ebpflow-tools/`: Tool to load eBPF code into eBPFlow 
- `usecases/`: eBPF network functions

## Quick start guidelines
1) You should load the bitstream file of the eBPFlow design with the Xilinx Vivado 16.04.

2) Compile ebpflow-tools 
  cd ebpflow-tools 
  make 
  make install
  
3) To load the network function on eBPFlow use the ebpflow-tools 

Usage: ebpflow-load [FLAGS] <ebpf-file.o>

Tool to load eBPF code into eBPFlow Switch.

Options: 

   -n                  Dry run without actually loading the code
   
   -x                  Show hex instructions after loading
   
   -d                  Disassemble instructions after loading
   
   -m MODE             Router mode to use (default is 1 [Router])
   
   -r RULES-FILE       Rules to be added to maps
   
   -s                  Checks and prints registers status
   
   -t                  Show table definitions
   
   -c MEM              Clean memory. See possible MEM values below
   
   -u MEM              Dump memory. See possible MEM values below
   
   -g                  Enable debug info (should be used with -s)
   
   -f                  Load instructions from raw .txt file
   
   -h                  Print this help message

MEM:
   
   1 -> TCAM
   
   2 -> CAM
 
## Use cases
- Wire: acts as a wire connecting adjacent ports in pairs of two. It performs an XOR operation between the input port value and 1, which inverts t    he least significant bit. This value defines the outgoing packet port. It is the most straightforward application and serves as a performance base    line.
  
- LPM Forwarding (LPMF): forwards packets using the NetFPGA's TCAM module, effectively speeding up longest prefix matching (LPM) operations. In ad    dition, this NF can use up to 32 forwarding rules inserted by the user through the loader.
  
- DDoS Mitigation (DDoS): tries to saturate broadband or overload networking equipment's computational resources, limiting the processing or makin    g unavailable services, servers, and the target network. This NF can analyze random ports of UDP packets. Moreover, it can block the attack on a s    pecific port, dropping the packet and not allowing the attack to have success.
  
- Stateful Firewall (SFW): is a network firewall that tracks the status and characteristics of network connections, distinguishing packets for dif    ferent types of communications and propagating only packets that match the active connections.
  
- SQL Injection with Tautology (SQL\_TAU): this attack is characterized by the insertion of tautologies in an SQL query, making them manipulable.     For example, if the system has the query {SELECT * FROM Users WHERE Id = “username”} where username is a user-supplied parameter. If no input filt    er exists, the attacker can exploit the vulnerability by sending the string {“OR 1 = 1} as a parameter.  The resulting query will be {SELECT * FRO    M Users WHERE Id = “” OR 1 = 1}, which is valid and returns all rows in the Users table, since 1 = 1 is always true.
  
- SQL Injection with Sleep function (SQL\_SLEEP): this attack allows hackers to look for possible SQL vulnerabilities on a server. It uses the Use    r-Agent field of HTTP requests to send an SQL query that calls the function sleep, applying a delay in seconds to the current operation. During th    e delay period, any further requests received run only after the end of the first query, which indicates to the attacker that there are vulnerabil    ities that allow the insertion of other SQL attacks.
  
- BitTorrent Packets (BITP): BitTorrent can cause many simultaneous connections, which can overload the network. This NF detects four BitTorrent p    acket types.
