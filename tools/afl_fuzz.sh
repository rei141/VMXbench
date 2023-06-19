export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
export AFL_SKIP_CPUFREQ=1
export AFL_DISABLE_TRIM=1
export AFL_INST_RATIO=0
export AFL_AUTORESUME=1
/home/ishii/nestedFuzz/AFLplusplus/afl-gcc -o tools/fuzz_auto tools/fuzz_auto.c

if [ "$2" = "c" ]; then
    tools/qemu_server "ivshmem_$3" "afl_bitmap_$3" > /dev/null 2>&1 &
    /home/ishii/nestedFuzz/AFLplusplus/afl-fuzz -i- -o "out/$1"/ -g 4096 -G 4096 -f afl_input -t 15000 -s 7 tools/fuzz_auto "ivshmem_$3" "afl_bitmap_$3"
elif [ "$2" = "M"  ]; then
    tools/qemu_server "ivshmem_$3" "afl_bitmap_$3" > /dev/null 2>&1 &
    /home/ishii/nestedFuzz/AFLplusplus/afl-fuzz -i ./small_input -o "out/$1" -M fuzzer$3 -g 4096 -G 4096 -f afl_input$3 -t 15000 -s 7 tools/fuzz_auto "ivshmem_$3" "afl_bitmap_$3" afl_input$3
elif [ "$2" = "S"  ]; then
    tools/qemu_server "ivshmem_$3" "afl_bitmap_$3" > /dev/null 2>&1 &
    /home/ishii/nestedFuzz/AFLplusplus/afl-fuzz -i ./small_input -o "out/$1" -S fuzzer$3 -g 4096 -G 4096 -f afl_input$3 -t 15000 -s 7 tools/fuzz_auto "ivshmem_$3" "afl_bitmap_$3" afl_input$3
else
    tools/qemu_server "ivshmem_$2" "afl_bitmap_$2" > /dev/null 2>&1 &
    /home/ishii/nestedFuzz/AFLplusplus/afl-fuzz -i ./random_input -o "out/$1" -g 4096 -G 4096 -f afl_input -t 15000 -s 7 tools/fuzz_auto "ivshmem_$2" "afl_bitmap_$2"
fi