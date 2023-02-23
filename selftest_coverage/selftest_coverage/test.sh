cat intel_* > tmp
cat tmp | sort | uniq > all_kvm_intel
cat kvm_* > tmp
cat tmp | sort | uniq > all_kvm