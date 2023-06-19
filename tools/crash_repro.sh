set -e
for var in `ls $1|grep $2`
do 
    echo "$1$var"
    sudo cp "$1$var" afl_input
    sudo tools/fuzz_auto
done