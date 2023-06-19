~/nestedFuzz/VMXbench/tools/create_cov_addr "$1"

addr2line -e /home/ishii/nestedFuzz/linux/arch/x86/kvm/kvm-intel.ko -i  < "cov_$1"| cut -d "/" -f5-| cut -d"(" -f1 | sed -e "s/ //g"|sed -e "s/\/.\//\//g"| sort | uniq > /tmp/tmp
# addr2line -e ~/nestedFuzz/linux/arch/x86/kvm/kvm-amd.ko -i  < "$1"| grep -v "\?"| cut -d "/" -f5-| cut -d"(" -f1 | sed -e "s/ //g"|sed -e "s/\/.\//\//g" |cut -d ":" -f -2 > /tmp/tmp 


cat /tmp/tmp  | grep -v "\.\." > /tmp/tmp1
cat /tmp/tmp  | grep "\.\." | ../tools/resolve_path.sh >> /tmp/tmp1
cat /tmp/tmp1 | sort -t: -k1,1 -k2n| uniq > "$2"

cat /tmp/tmp |grep nested.c: | sort | uniq | cut -d ":" -f2 | cut -d"(" -f1 | sed -e "s/ //g" | perl -e '@l=<>;print sort {hex($a)<=>hex($b)} @l'