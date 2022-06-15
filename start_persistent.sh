# rm kvm_intel_coverage kvm_coverage
export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
export AFL_SKIP_CPUFREQ=1
export AFL_DISABLE_TRIM=1
export AFL_INST_RATIO=100
export AFL_MAP_SIZE=10000000
/home/ishii/work/AFLplusplus/afl-clang-fast -o persitent_call persitent_call.c 
# /home/ishii/nestedFuzz/AFLplusplus/afl-fuzz -i ./input/ -o out17/ -g 4096 -G 4096 -f image/input  -t 10000 ./caller
/home/ishii/work/AFLplusplus/afl-fuzz -i ./input/ -o out3/ -g 4096 -G 4096 -t 5000 -f ./afl_input ./persitent_call
