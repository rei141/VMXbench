#!/bin/bash

# Get the PID of the process
pid=$(ps aux | grep 'sudo ./qemu_server' | awk '{print $2}')

# Kill the process with the PID
kill $pid
