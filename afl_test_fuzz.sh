export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
export AFL_SKIP_CPUFREQ=1
export AFL_DISABLE_TRIM=1
export AFL_INST_RATIO=0
export AFL_AUTORESUME=1
# /home/ishii/work/AFLplusplus/afl-gcc -o fuzz_test fuzz_test.c
# /home/ishii/work/AFLplusplus/afl-fuzz -i ./input/ -o "out/$1"/ -g 2048 -G 2048 -f afl_input -t 1000 -s 7 ./fuzz_test
/home/ishii/work/AFLplusplus/afl-gcc -o fuzz_auto fuzz_auto.c
/home/ishii/work/AFLplusplus/afl-fuzz -i ./random_input/ -o "out/$1"/ -g 2048 -G 2048 -f afl_input -t 10000 -s 7 ./fuzz_auto