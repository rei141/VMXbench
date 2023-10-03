#!/bin/bash

if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <filename> <coverage_file_path>"
    exit 1
fi

filename=$1
coverage_file_path=$2

awk -v file="$filename" '
BEGIN { print_data=0 }
$0 ~ "  -:    0:Source:" && print_data { exit }
$0 ~ "Source:"file { print_data=1 }
print_data { print }
' "$coverage_file_path"