echo $1 | python3 ../sub5.py > "raw_$2"
addr2line -e ~/nestedFuzz/linux/arch/x86/kvm/kvm-intel.ko -if < "raw_$2" > "$2_nested"

# echo $1 | python3 sub-4.py > tmp
addr2line -e ~/nestedFuzz/linux/arch/x86/kvm/kvm-intel.ko -if < "raw_$2"  > "$2_vmx"
