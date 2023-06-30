#!/bin/bash
set -e

if [ -z "$1" ]
then
    echo "coverage file is required."
    exit 1
fi

LINE_OUT=$2
if [ -z "$2" ]
then
    LINE_OUT="tmp"
fi

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

source $SCRIPT_DIR/utilities.sh

COV_OUT=$($SCRIPT_DIR/../create_cov_addr "$1")
check_file $COV_OUT

check_file $CONFIG_PATH

KVM_DIR=$(python3 $SCRIPT_DIR/get_yaml.py $CONFIG_PATH directories kvm)

addr2line -e $KVM_DIR/kvm-${arch}.ko -i  < $COV_OUT| cut -d "/" -f5-| cut -d"(" -f1 | sed -e "s/ //g"|sed -e "s/\/.\//\//g"| sort | uniq > /tmp/tmp

cat /tmp/tmp  | grep -v "\.\." > /tmp/tmp1
cat /tmp/tmp  | grep "\.\." | $SCRIPT_DIR/resolve_path.sh >> /tmp/tmp1
cat /tmp/tmp1 | sort -t: -k1,1 -k2n| uniq > "$LINE_OUT"

cat /tmp/tmp |grep nested.c: | sort | uniq | cut -d ":" -f2 | cut -d"(" -f1 | sed -e "s/ //g" | perl -e '@l=<>;print sort {hex($a)<=>hex($b)} @l'