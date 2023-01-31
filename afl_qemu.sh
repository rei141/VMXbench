# rm kvm_intel_coverage kvm_coverage
export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
export AFL_SKIP_CPUFREQ=1
export AFL_DISABLE_TRIM=1
export AFL_INST_RATIO=0
export AFL_AUTORESUME=1
/home/ishii/nestedFuzz/AFLplusplus/afl-gcc -o caller caller.c
# /home/ishii/nestedFuzz/AFLplusplus/afl-fuzz -i ./input/ -o out17/ -g 4096 -G 4096 -f image/input  -t 10000 ./caller
/home/ishii/nestedFuzz/AFLplusplus/afl-fuzz -i ./input/ -o out2/ -g 4096 -G 4096 -t 7000 ./caller
