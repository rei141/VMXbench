addr2line -e ~/nestedFuzz/linux/arch/x86/kvm/kvm-intel.ko -i < $1| cut -d "/" -f5-| cut -d"(" -f1 | sed -e "s/ //g"|sed -e "s/\/.\//\//g"| sort | uniq > tmp

cat tmp |grep nested.c: | sort | uniq | cut -d ":" -f2 | cut -d"(" -f1 | sed -e "s/ //g"> tmp1
perl -e '@l=<>;print sort {hex($a)<=>hex($b)} @l' < tmp1 | sed "s/ //g" | uniq > "cov_nested_$2"

perl -e '@l=<>;print sort {hex($a)<=>hex($b)} @l' < tmp > "cov_all_$2"