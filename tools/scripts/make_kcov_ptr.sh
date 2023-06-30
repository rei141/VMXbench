#!/bin/bash
set -e
mkdir -p kcov_baseline

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

source $SCRIPT_DIR/utilities.sh

check_file $CONFIG_PATH

KVM_DIR=$(python3 $SCRIPT_DIR/get_yaml.py $CONFIG_PATH directories kvm)

objdump -d -M intel $KVM_DIR/kvm-$arch.ko -r | grep cov_trace_pc | grep R_X86_64_PLT32 | cut -d ":" -f1 | sed 's/^[ \t]*//' | sed 's/^/0x/g' > "kcov_baseline/kvm_$arch"
# echo "$1" | python3 ~/tmp/add.py > "$1-1"
echo "kcov_baseline/kvm_$arch" | python3 $SCRIPT_DIR/add4.py > "/tmp/tmp"

# cp kcov_baseline/kvm_intel tmp
perl -e '@l=<>;print sort {hex($a)<=>hex($b)} @l' < "/tmp/tmp" | uniq > "kcov_baseline/kvm_$arch"

addr2line -e $KVM_DIR/kvm-$arch.ko -i  < "kcov_baseline/kvm_$arch"| cut -d "/" -f5-| cut -d"(" -f1 | sed -e "s/ //g"|sed -e "s/\/.\//\//g"| sort | uniq > /tmp/tmp
# addr2line -e ~/nestedFuzz/linux/arch/x86/kvm/kvm-amd.ko -i  < "$1"| grep -v "\?"| cut -d "/" -f5-| cut -d"(" -f1 | sed -e "s/ //g"|sed -e "s/\/.\//\//g" |cut -d ":" -f -2 > /tmp/tmp 


cat /tmp/tmp  | grep -v "\.\." > /tmp/tmp1
cat /tmp/tmp  | grep "\.\." | $SCRIPT_DIR/resolve_path.sh >> /tmp/tmp1
cat /tmp/tmp1 | sort -t: -k1,1 -k2n| uniq > "kcov_baseline/kvm_"$arch"_all"

objdump -d -M intel $KVM_DIR/kvm.ko -r | grep cov_trace_pc | grep R_X86_64_PLT32 | cut -d ":" -f1 | sed 's/^[ \t]*//' | sed 's/^/0x/g' > "kcov_baseline/kvm"
# echo "$1" | python3 ~/tmp/add.py > "$1-1"
echo "kcov_baseline/kvm" | python3 $SCRIPT_DIR/add4.py > "/tmp/tmp"
# cp kcov_baseline/kvm tmp
perl -e '@l=<>;print sort {hex($a)<=>hex($b)} @l' < "/tmp/tmp" | uniq > "kcov_baseline/kvm"

addr2line -e $KVM_DIR/kvm.ko -i < "kcov_baseline/kvm" | cut -d "/" -f5-| cut -d ":" -f -2 | cut -d"(" -f1| sed -e "s/ //g" | sed -e "s/\/.\//\//g"> /tmp/tmp 
# eu-addr2line -e ~/nestedFuzz/linux/arch/x86/kvm/kvm.ko -i < "kcov_baseline/kvm" | grep -v "\?"| cut -d ":" -f -2 | cut -d"(" -f1| sed -e "s/ //g" | sed -e "s/\/.\//\//g"|sed -e "s/^.\///g" |sed -e "s/^/linux\//g" > tmp
cat /tmp/tmp  | grep -v "\.\." > /tmp/tmp1
cat /tmp/tmp  | grep "\.\." | $SCRIPT_DIR/resolve_path.sh >> /tmp/tmp1
cat /tmp/tmp1 | sort -t: -k1,1 -k2n| uniq > "kcov_baseline/kvm_all"