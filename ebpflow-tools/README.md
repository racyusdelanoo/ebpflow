# **ebpflow-tools**

This repository contains the source code of tools to help development and interaction with the EBPFlow switch.

## **ebpflow-cli** : Interact with EBPFlow switch

    $ ebpflow-cli

    >>>>>>>>>>>>>>>>>>>>>>>>> eBPFlow Switch <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<

    =========================== Commands ===================================
    install       - Install the instructions in the switch
    status        - List value registers
    menu          - Display this menu
    help          - Shows help menu
    quit          - Exit this program
    ========================================================================


    >>>

## **ebpflow-disasm** : Disassemble eBPF code

    $ ebpflow-disasm -h

    Usage: ebpflow-disasm [FLAGS] <ebpf-file.o>
    Disassembles eBPF code into human-readable format.

    Options:
    -o [outfile]    Output to file
    -h              Print this help message

## **ebpflow-load** : Load code to EBPFlow switch

    $ ebpflow-load -h

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
	   -p                  Enable payload processing
	   -g                  Enable debug info (should be used with -s)
	   -f                  Load instructions from raw .txt file
	   -h                  Print this help message

	MEM:
	   1 -> TCAM
	   2 -> CAM

	Currently the -f flag is not compatible with the other options, thus
	should be used by itself with the corresponding argument.


Example: Installing iprouter example with rules

    $ ebpflow-load -r examples/rules/iprouter.rules examples/iprouter.o

## **ebpflow-test** : Simulate eBPF code execution on EBPFlow switch

    $ ebpflow-test -h

    Usage: ebpflow-test [FLAGS] -f <pcap-file> <ebpf-file.o>
    Tool to test eBPF code on eBPFlow Switch emulator.

    Options:
    -f PCAP-FILE             Input pcap file (required)
    -r RULES-FILE            Rules to be added to maps before running the code
    -a                       Show packet before running code
    -b                       Show packet after running code
    -o FILE                  Output modified packets to file
    -p PORT                  Choose packets input port (Fixed, for now)
    -h                       Print this help message

## **Serverless platform**

### Controller

    $ cd serverless/api
    $ make
    $ controller/cli.py

	--------------------------------------------------------------------------------
		eBPFlow Controller Command Line Interface - Winet 2019
		Matheus Castanho <matheus.castanho@dcc.ufmg.br> - Universidade Federal de Minas Gerais
	--------------------------------------------------------------------------------


	Documented commands (type help <topic>):
	========================================
	allocate  help

	Undocumented commands:
	======================
	EOF  connections

	ebpflow>>
	
### **Scheduler**
    
    $ serverless/scheduler --help
	
	Usage: scheduler [OPTION...] [FLAGS]
	eBPFlow Scheduler -- Scheduler for serverless platform

	  -c, --controller=address   Controller address (default 127.0.0.1:9000)
	  -i, --id=id                Scheduler ID number (default is random)
	  -?, --help                 Give this help list
		  --usage                Give a short usage message
	  -V, --version              Print program version

	Mandatory or optional arguments to long options are also mandatory or optional
	for any corresponding short options.

	Report bugs to <matheus.castanho@dcc.ufmg.br>

## **Installation**

### Ubuntu

First install the dependencies needed:

    sudo apt install gcc make libelf-dev libpcap-dev linux-headers-$(uname -r) protobuf-compiler protobuf-c-compiler libprotobuf-c-dev
    pip3 install twisted protobuf

Next, download the code from this repository:

    git clone https://bitbucket.org/projetonetfpga/ebpflow-tools.git

Then compile and install the tools:

    cd ebpflow-tools
    make
    sudo make install

**Obs**: If you face the following error:

	/usr/include/linux/types.h:4:10: fatal error: 'asm/types.h' file not found #include <asm/types.h>

Try installing the package `libc6-dev-i386`:

	sudo apt-get install libc6-dev-i386
