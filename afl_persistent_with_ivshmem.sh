export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
export AFL_SKIP_CPUFREQ=1
export AFL_DISABLE_TRIM=1
export AFL_INST_RATIO=0
/home/ishii/work/AFLplusplus/afl-gcc -o fuzz_with_ivshmem fuzz_with_ivshmem.c
/home/ishii/work/AFLplusplus/afl-fuzz -i ./input/ -o out06_20/ -g 4096 -G 4096 -f afl_input -t 1000 ./fuzz_with_ivshmem