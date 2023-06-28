#!/bin/bash
mkdir -p kcov_baseline

cpu_vendor=$(grep -m1 vendor_id /proc/cpuinfo | awk -F ":" '{print $2}' | tr -d ' ')

if [ "$cpu_vendor" = "GenuineIntel" ]; then
    arch="intel"
elif [ "$cpu_vendor" = "AuthenticAMD" ]; then
    arch="amd"
else
    echo "Unknown CPU vendor"
fi

objdump -d -M intel ~/work/linux/arch/x86/kvm/kvm-$arch.ko -r | grep cov_trace_pc | grep R_X86_64_PLT32 | cut -d ":" -f1 | sed 's/^[ \t]*//' | sed 's/^/0x/g' > "kcov_baseline/kvm_$arch"
# echo "$1" | python3 ~/tmp/add.py > "$1-1"
echo "kcov_baseline/kvm_$arch" | python3 tools/add4.py > "/tmp/tmp"

# cp kcov_baseline/kvm_intel tmp
perl -e '@l=<>;print sort {hex($a)<=>hex($b)} @l' < "/tmp/tmp" | uniq > "kcov_baseline/kvm_$arch"

addr2line -e /home/ishii/work/linux/arch/x86/kvm/kvm-$arch.ko -i  < "kcov_baseline/kvm_$arch"| cut -d "/" -f5-| cut -d"(" -f1 | sed -e "s/ //g"|sed -e "s/\/.\//\//g"| sort | uniq > /tmp/tmp
# addr2line -e ~/work/linux/arch/x86/kvm/kvm-amd.ko -i  < "$1"| grep -v "\?"| cut -d "/" -f5-| cut -d"(" -f1 | sed -e "s/ //g"|sed -e "s/\/.\//\//g" |cut -d ":" -f -2 > /tmp/tmp 


cat /tmp/tmp  | grep -v "\.\." > /tmp/tmp1
cat /tmp/tmp  | grep "\.\." | tools/resolve_path.sh >> /tmp/tmp1
cat /tmp/tmp1 | sort -t: -k1,1 -k2n| uniq > "kcov_baseline/kvm_"$arch"_all"

objdump -d -M intel ~/work/linux/arch/x86/kvm/kvm.ko -r | grep cov_trace_pc | grep R_X86_64_PLT32 | cut -d ":" -f1 | sed 's/^[ \t]*//' | sed 's/^/0x/g' > "kcov_baseline/kvm"
# echo "$1" | python3 ~/tmp/add.py > "$1-1"
echo "kcov_baseline/kvm" | python3 tools/add4.py > "/tmp/tmp"
# cp kcov_baseline/kvm tmp
perl -e '@l=<>;print sort {hex($a)<=>hex($b)} @l' < "/tmp/tmp" | uniq > "kcov_baseline/kvm"

addr2line -e ~/work/linux/arch/x86/kvm/kvm.ko -i < "kcov_baseline/kvm" | cut -d "/" -f5-| cut -d ":" -f -2 | cut -d"(" -f1| sed -e "s/ //g" | sed -e "s/\/.\//\//g"> /tmp/tmp 
# eu-addr2line -e ~/work/linux/arch/x86/kvm/kvm.ko -i < "kcov_baseline/kvm" | grep -v "\?"| cut -d ":" -f -2 | cut -d"(" -f1| sed -e "s/ //g" | sed -e "s/\/.\//\//g"|sed -e "s/^.\///g" |sed -e "s/^/linux\//g" > tmp
cat /tmp/tmp  | grep -v "\.\." > /tmp/tmp1
cat /tmp/tmp  | grep "\.\." | tools/resolve_path.sh >> /tmp/tmp1
cat /tmp/tmp1 | sort -t: -k1,1 -k2n| uniq > "kcov_baseline/kvm_all"