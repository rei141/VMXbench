#!/bin/bash

# coverage_traceファイルを分割
find /tmp -name 'coverage_trace_split*' -delete
split -n l/24 coverage_trace /tmp/coverage_trace_split

# 各分割ファイルにaddr2lineを並列実行
parallel --will-cite --progress "cat {} | while read -r line; do if [[ \$line == '0x'* ]]; then addr2line -e /home/ishii/nestedFuzz/linux/arch/x86/kvm/kvm-intel.ko -afi <<< \"\$line\" >> {}.line; else addr2line -e /home/ishii/nestedFuzz/linux/arch/x86/kvm/kvm.ko -afi <<< \"\$line\" >> {}.line; fi done" ::: /tmp/coverage_trace_split*

# 結果を一つのファイルにまとめる
cat /tmp/coverage_trace_split*.line > coverage_trace_line_afi