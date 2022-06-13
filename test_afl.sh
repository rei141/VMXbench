export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
export AFL_SKIP_CPUFREQ=1
export AFL_DISABLE_TRIM=1
export AFL_INST_RATIO=0
/home/ishii/work/AFLplusplus/afl-gcc -o caller caller.c
/home/ishii/work/AFLplusplus/afl-fuzz -i ./input/ -o out16/ -g 4096 -G 4096 -f image/input -t 10000 ./caller