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
    /home/ishii/nestedFuzz/AFLplusplus/afl-fuzz -i ./random_input -o "out/$1" -M fuzzer$3 -g 4096 -G 4096 -f afl_input_$3 -t 15000 -s 7 tools/fuzz_auto "ivshmem_$3" "afl_bitmap_$3" afl_input_$3
elif [ "$2" = "S"  ]; then
    tools/qemu_server "ivshmem_$3" "afl_bitmap_$3" > /dev/null 2>&1 &
    /home/ishii/nestedFuzz/AFLplusplus/afl-fuzz -i ./random_input -o "out/$1" -S fuzzer$3 -g 4096 -G 4096 -f afl_input_$3 -t 15000 -s 7 tools/fuzz_auto "ivshmem_$3" "afl_bitmap_$3" afl_input_$3
elif [ -z "$2" ]; then
    # tools/qemu_server "ivshmem_$2" "afl_bitmap_$2" > /dev/null 2>&1 &
    /home/ishii/work/AFLplusplus/afl-fuzz -i ./random_input -o "out/$1" -g 4096 -G 4096 -f afl_input -t 15000 -s 7 tools/fuzz_auto "ivshmem" "afl_bitmap"
else
    echo "Usage: afl_fuzz.sh <output_directory> <operation> <fuzzer_id>"
    echo ""
    echo "This script runs AFLplusplus with various configuration options."
    echo ""
    echo "Arguments:"
    echo "<output_directory>  - Directory where AFL will write its output."
    echo "<operation>         - The operation mode. Options are 'c', 'M', or 'S'."
    echo "   'c' - Run the fuzzing job without additional coverage instrumentation and reporting."
    echo "   'M' - Run the fuzzing job as the master process in a multi-fuzzing setup."
    echo "   'S' - Run the fuzzing job as a secondary process in a multi-fuzzing setup."
    echo "<fuzzer_id>         - An ID for the fuzzing process. It's used in the creation of shared memory segments and other identifiers."
    echo ""
    echo "Example:"
    echo "  afl_fuzz.sh output_dir M 1"
    echo "  This command will run the fuzzing job as the master process and output results to the 'output_dir' directory."
fi
