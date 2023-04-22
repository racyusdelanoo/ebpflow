#!/usr/bin/env python3

import cmd
import readline
import signal
import os
import subprocess as sp

class EBPFlowCLI(cmd.Cmd):
    cmds_banner = """
=========================== Commands ===================================
  install       - Install the instructions in the switch
  status        - List value registers
  menu          - Display this menu
  help          - Shows help menu
  quit          - Exit this program
========================================================================
"""

    intro = """
>>>>>>>>>>>>>>>>>>>>>>>>> eBPFlow Switch <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
%s
""" % cmds_banner

    prompt = '>>> '

    def do_install(self, arg):
        args = arg.split()

        if len(args) != 2:
            print("Error: Expected 2 arguments to `install`, not %d" % len(args))
            return

        mode = args[0]
        filepath = args[1]

        # TODO: ebpflow-load should be installed in the system
        try:
            sp.call(["ebpflow-load","-m",mode,filepath])
        except:
            print("Failed to run `ebpflow-load`. Is it installed?")

    def help_install(self):
        print("Installs the code from FILE into the switch using mode MODE\n")
        print("> install MODE FILE")
        print("  MODE: 0: Test // 1: Router")
        print("  FILE: path to .o BPF compiled code")

    def do_status(self, arg):
        args = arg.split()

        if len(args) != 0:
            print("Warning: `status` expects no arguments, ignoring...")

        try:
            sp.call(["ebpflow-load","-s"])
        except:
            print("Failed to run `ebpflow-load`. Is it installed?")

    def help_status(self):
        print("Issues a read for register R0 and WRINST and prints their values\n")
        print("> status")

    def do_menu(self, arg):
        print(self.cmds_banner)

    def help_menu(self):
        print("Shows the commands menu\n")
        print("> menu")

    def do_quit(self, arg):
        quit()

    def help_quit(self):
        print("Exists the program\n")
        print("> quit")

if __name__ == "__main__":
    try:
        EBPFlowCLI().cmdloop()
    except KeyboardInterrupt:
        print()
    finally:
        # TODO: Any cleaning up to do?
        pass