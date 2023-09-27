#!/bin/bash
set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

source $SCRIPT_DIR/utilities.sh

check_file $CONFIG_PATH

WORK_DIR=$(python3 $SCRIPT_DIR/get_yaml.py $CONFIG_PATH directories work_dir)

python3 $SCRIPT_DIR/binc.py $1 $WORK_DIR/src/binc.h $WORK_DIR/src/binc.c  