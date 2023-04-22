# eBPFlow examples

## Compiling

The `Makefile` present on this directory already compiles all examples terminating in `.c` and generates the corresponding `.o` file.

## Loading programs

To load the examples, use the tool `ebpflow-load` that is present on the `tools/` folder under the root of this repo. For extra flags and loading parameters, please check `ebpflow-load` documentation (`ebpflow-load -h`).

    ebpflow-load <program.o>

## Programs with external rules

Some programs require the installation of rules on the CAM and TCAM. On these cases, the flag `-r` along with the file containing the rules should be provided during load.

    ebpflow-load -r rules/iprouter.rules iprouter.o

The syntax of the rules file is very straightforward. Just check some examples under `rules/`.
