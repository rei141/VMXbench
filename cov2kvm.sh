../create_cov_addr "$1"
addr2line -e ~/nestedFuzz/linux/arch/x86/kvm/kvm.ko -i < "cov_$1"| cut -d "/" -f5-| cut -d"(" -f1 | sed -e "s/ //g"|sed -e "s/\/.\//\//g"| sort | uniq > tmp

# cat tmp |grep nested.c: | sort | uniq | cut -d ":" -f2 | cut -d"(" -f1 | sed -e "s/ //g"> tmp1
# perl -e '@l=<>;print sort {hex($a)<=>hex($b)} @l' < tmp1 | sed "s/ //g" | uniq > "tmp_nested_$2" 

perl -e '@l=<>;print sort {hex($a)<=>hex($b)} @l' < tmp > "tmp_kvm_$2"