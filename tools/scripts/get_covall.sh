# echo $1 | python3 ../sub5.py > "raw_$2"
# addr2line -e ~/nestedFuzz/linux/arch/x86/kvm/kvm-intel.ko -if < "raw_$2" > "$2_nested"

# # echo $1 | python3 sub-4.py > tmp
# addr2line -e ~/nestedFuzz/linux/arch/x86/kvm/kvm-intel.ko -if < "raw_$2"  > "$2_vmx"
WORK_DIR="`pwd`"
echo $WORK_DIR
mkdir -p cov
mkdir -p out

for file in `ls $WORK_DIR | grep "^n_arch"`; do
    # echo $file

    if [ -e "cov/cov_$file" ]; then
        continue
    fi
    /home/ishii/nestedFuzz/VMXbench/tools/create_cov_addr $file
    mv "cov_$file" cov/
    addr2line -e ~/nestedFuzz/linux/arch/x86/kvm/kvm-intel.ko -i  < "cov/cov_$file"| cut -d "/" -f5-| cut -d"(" -f1 | sed -e "s/ //g"|sed -e "s/\/.\//\//g"| sort | uniq > tmp
    cat tmp |grep nested.c: | sort | uniq | cut -d ":" -f2 | cut -d"(" -f1 | sed -e "s/ //g"> tmp1
    # cp tmp1 > "out/nested/$file"
    # echo $out
    out="`echo $file | sed 's/^[^0-9]*\([0-9]\{2\}_[0-9]\{2\}_[0-9]\{2\}\).*/\1/'`"
    perl -e '@l=<>;print sort {hex($a)<=>hex($b)} @l' < tmp1 | sed "s/ //g" | uniq > "out/$out"
done

cnt=0
for file in `ls out`; do
    # echo $file
    # /home/ishii/nestedFuzz/VMXbench/create_cov_addr $file
    # mv "cov_$file" cov/
    # addr2line -e ~/nestedFuzz/linux/arch/x86/kvm/kvm-intel.ko -i  < "cov/cov_$file"| cut -d "/" -f5-| cut -d"(" -f1 | sed -e "s/ //g"|sed -e "s/\/.\//\//g"| sort | uniq > tmp
    # cat tmp |grep nested.c: | sort | uniq | cut -d ":" -f2 | cut -d"(" -f1 | sed -e "s/ //g"> tmp1
    # out="`echo $file | sed 's/^[^0-9]*\([0-9]\{2\}_[0-9]\{2\}_[0-9]\{2\}\).*/\1/'`"
    # echo $out
    # perl -e '@l=<>;print sort {hex($a)<=>hex($b)} @l' < tmp1 | sed "s/ //g" | uniq > "out/$out"
    num=`echo $file | sed -e "s/.*_\([0-9]\{2\}\)$/\1/"`
    # cnt=`wc out/$file -l | sed -e "s/^[0-9].*/\1/"`
    cnt=`wc out/$file -l | sed -e "s/^\([0-9]\+\).*/\1/"`

    echo $num $cnt
done