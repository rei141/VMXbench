addr2line -e ~/nestedFuzz/linux/arch/x86/kvm/kvm-amd.ko -i  < "kcov_baseline/kvm_amd"| grep -v "\?"| cut -d "/" -f5-| cut -d"(" -f1 | sed -e "s/ //g"|sed -e "s/\/.\//\//g" |cut -d ":" -f -2 > /tmp/tmp 
# eu-addr2line -e ~/nestedFuzz/linux/arch/x86/kvm/kvm-intel.ko -i  < "kcov_baseline/kvm_intel"| grep -v "\?"| cut -d"(" -f1 | sed -e "s/ //g"|sed -e "s/\/.\//\//g" |sed -e "s/^.\///g"|cut -d ":" -f -2 |sed -e "s/^/linux\//g"> tmp 
cat /tmp/tmp  | grep -v "\.\." > /tmp/tmp1
cat /tmp/tmp  | grep "\.\." | tools/resolve_path.sh >> /tmp/tmp1
cat /tmp/tmp1 | sort -t: -k1,1 -k2n| uniq > "kcov_baseline/kvm_amd_all"

cat "kcov_baseline/kvm_amd_all" |grep nested.c: | sort | uniq | cut -d ":" -f2 | cut -d"(" -f1 | sed -e "s/ //g"> /tmp/tmp1
perl -e '@l=<>;print sort {hex($a)<=>hex($b)} @l' < /tmp/tmp1 | sed "s/ //g" | uniq > "kcov_baseline/kvm_amd_nested"

addr2line -e ~/nestedFuzz/linux/arch/x86/kvm/kvm-amd.ko -if  < "kcov_baseline/kvm_amd"| grep -v "\?"| cut -d "/" -f5-| cut -d"(" -f1 | sed -e "s/ //g"|sed -e "s/\/.\//\//g" |cut -d ":" -f -2 > /tmp/tmp  
cat /tmp/tmp  | grep nested.c: -B 1 | grep -v "\-\-" | awk -F':' '{
    if (NR%2==1) {
        funcname=$1
    } else {
        split($2, a, ":")
        print a[1], funcname
    }
}' | sort -n | uniq > kcov_baseline/kvm_amd_nested_func
# echo "baseline/kvm_intel_nested" | python3 make_nested_c.py 

# # echo $1 | python3 sub-4.py > tmp
# cat "baseline/kvm_intel_all" |grep vmx.c: | sort | uniq | cut -d ":" -f2 | cut -d"(" -f1 > tmp1
# perl -e '@l=<>;print sort {hex($a)<=>hex($b)} @l' < tmp1 > "baseline/kvm_intel_vmx"

# echo "baseline/kvm_intel_vmx" | python3 make_vmx_c.py 

addr2line -e ~/nestedFuzz/linux/arch/x86/kvm/kvm.ko -i < "kcov_baseline/kvm" | cut -d "/" -f5-| cut -d ":" -f -2 | cut -d"(" -f1| sed -e "s/ //g" | sed -e "s/\/.\//\//g"> /tmp/tmp 
# eu-addr2line -e ~/nestedFuzz/linux/arch/x86/kvm/kvm.ko -i < "kcov_baseline/kvm" | grep -v "\?"| cut -d ":" -f -2 | cut -d"(" -f1| sed -e "s/ //g" | sed -e "s/\/.\//\//g"|sed -e "s/^.\///g" |sed -e "s/^/linux\//g" > tmp
cat /tmp/tmp  | grep -v "\.\." > /tmp/tmp1
cat /tmp/tmp  | grep "\.\." | tools/resolve_path.sh >> /tmp/tmp1
cat /tmp/tmp1 | sort -t: -k1,1 -k2n| uniq > "kcov_baseline/kvm_all"

# cat "baseline/kvm_intel_all" | cut -d ":" -f1 | uniq -c |sort -n -r > "baseline/line_kvm_intel_all"
# cat "baseline/line_kvm_intel_all"  | awk -F" " '{print "|" $2"|" $1"|"}' >"baseline/line_kvm_intel_all_table"

# cat "baseline/kvm_all" | cut -d ":" -f1 | uniq -c |sort -n -r > "baseline/line_kvm_all"
# cat "baseline/line_kvm_all"  | awk -F" " '{print "|" $2"|" $1"|"}' >"baseline/line_kvm_all_table"

# cat baseline/kvm_all baseline/kvm_intel_all | sort -t: -k1,1 -k2n| uniq > baseline/all_all

# cat "baseline/all_all" | cut -d ":" -f1 | uniq -c |sort -n -r > "baseline/line_all_all"
# cat "baseline/line_all_all"  | awk -F" " '{print "|" $2"|" $1"|"}' >"baseline/line_all_all_table"