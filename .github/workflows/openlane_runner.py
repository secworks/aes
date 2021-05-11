#!/usr/bin/python3

#This script is a launcher script for Edalize
#Normally Edalize will launch the EDA tools directly, but if the
#EDALIZE_LAUNCHER environmnet variable is set and points to an executable file,
#this file will be called with the command-line that Edalize would otherwise
#have launched.
#
#This allows us to define a custom launcher, as in this case where we intercept
#the call to flow.tcl (the entry point to the openlane flow) and start up a
#container. If Edalize wants to execute other applications, we just start them
#the normal way

import os
import subprocess
import sys

def enverr(e):
    print(f"Error: Openlane backend needs environment variable '{e}' to be set")
    exit(1)

if 'flow.tcl' in sys.argv[1]:
    pdk_root      = os.environ.get('PDK_ROOT') or enverr('PDK_ROOT')
    (build_root, work) = os.path.split(os.getcwd())

    image = "efabless/openlane:v0.12"

    prefix = ["docker", "run",
              "-v", f"{pdk_root}:{pdk_root}",
              "-v", f"{build_root}:/project",
              "-e", f"PDK_ROOT={pdk_root}",
              "-u", f"{os.getuid()}:{os.getgid()}",
              "-w", f"/project/{work}",
              image]
    sys.exit(subprocess.call(prefix+sys.argv[1:]))
else:
    sys.exit(subprocess.call(sys.argv[1:]))
    
