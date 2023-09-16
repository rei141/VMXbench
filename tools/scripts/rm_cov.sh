#!/bin/bash

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

source $SCRIPT_DIR/utilities.sh
check_file $CONFIG_PATH
WORK_DIR=$(python3 ./tools/scripts/get_yaml.py $CONFIG_PATH directories work_dir)

echo $WORK_DIR
sudo rm $WORK_DIR/total_kvm_arch_coverage $WORK_DIR/total_kvm_coverage -f
sudo rm /dev/shm/kvm_arch_coverage /dev/shm/kvm_coverage -f

if [ "$1" = "record"  ]; then
    sudo rm $WORK_DIR/record/out/* $WORK_DIR/record/cov/* $WORK_DIR/record/*
fi