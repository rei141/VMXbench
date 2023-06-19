objdump -d -M intel ~/nestedFuzz/linux/arch/x86/kvm/kvm-amd.ko -r | grep cov_trace_pc | grep R_X86_64_PLT32 | cut -d ":" -f1 | sed 's/^[ \t]*//' | sed 's/^/0x/g' > "kcov_baseline/kvm_amd"
# echo "$1" | python3 ~/tmp/add.py > "$1-1"
echo "kcov_baseline/kvm_amd" | python3 tools/add4.py > "/tmp/tmp"

# cp kcov_baseline/kvm_intel tmp
perl -e '@l=<>;print sort {hex($a)<=>hex($b)} @l' < "/tmp/tmp" | uniq > "kcov_baseline/kvm_amd"

tools/cov2nested.sh  kcov_baseline/kvm_amd kcov_baseline/kvm_amd_all
objdump -d -M intel ~/nestedFuzz/linux/arch/x86/kvm/kvm.ko -r | grep cov_trace_pc | grep R_X86_64_PLT32 | cut -d ":" -f1 | sed 's/^[ \t]*//' | sed 's/^/0x/g' > "kcov_baseline/kvm"
# echo "$1" | python3 ~/tmp/add.py > "$1-1"
echo "kcov_baseline/kvm" | python3 tools/add4.py > "/tmp/tmp"
# cp kcov_baseline/kvm tmp
perl -e '@l=<>;print sort {hex($a)<=>hex($b)} @l' < "/tmp/tmp" | uniq > "kcov_baseline/kvm"