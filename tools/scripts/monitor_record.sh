#!/bin/bash
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

source $SCRIPT_DIR/utilities.sh
CURRENT_DIR="`pwd`"
echo $CURRENT_DIR

check_file $CONFIG_PATH

COVOUT_DIR=$(python3 $SCRIPT_DIR/get_yaml.py $CONFIG_PATH directories covout_dir)
mkdir -p $COVOUT_DIR/cov
mkdir -p $COVOUT_DIR/out

for file in `ls $CURRENT_DIR | grep "^n_arch"`; do
    if [ -e "out/$file" ]; then
        continue
    fi
    $SCRIPT_DIR/cov2nested.sh ${file} "out/${file}" > /dev/null
    grep -c "nested.c" "$COVOUT_DIR/out/${file}"
    mv "cov_$file" "$COVOUT_DIR/cov/cov_$file"
done
inotifywait -m "$CURRENT_DIR" -e create -e moved_to |
    while read path action file; do
        # 新しく作成されたファイルが "^n_arch" にマッチするかを確認します。
        if [[ $file =~ ^n_arch ]]; then
            # echo "The file '$file' appeared in directory '$path' via '$action'"
            # コマンドを実行します。
            echo ${path}${file}
            $SCRIPT_DIR/cov2nested.sh ${file} "${path}out/${file}" > /dev/null
            grep -c "nested.c" "${path}out/${file}"
            mv "${path}cov_$file" "${path}cov/cov_$file"
        fi
    done