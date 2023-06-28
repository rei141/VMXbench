#!/bin/bash

WORK_DIR="`pwd`"
echo $WORK_DIR
mkdir -p cov
mkdir -p out

inotifywait -m "$WORK_DIR" -e create -e moved_to |
    while read path action file; do
        # 新しく作成されたファイルが "^n_arch" にマッチするかを確認します。
        if [[ $file =~ ^n_arch ]]; then
            # echo "The file '$file' appeared in directory '$path' via '$action'"
            # コマンドを実行します。
            echo ${path}${file}
            /home/ishii/work/VMXbench/tools/cov2nested.sh ${file} "${path}out/${file}" > /dev/null
            grep -c "nested.c" "${path}out/${file}"
            mv "${path}cov_$file" "${path}cov/cov_$file"
        fi
    done