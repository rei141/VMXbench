#!/bin/bash

PREV_FILE="/tmp/xl_dmesg_prev.log"
CURRENT_FILE="/tmp/xl_dmesg_current.log"

# 初期のxl dmesgの出力を保存
sudo xl dmesg > $PREV_FILE

while true; do
    # xl dmesg の出力を保存
    sudo xl dmesg > $CURRENT_FILE

    # 前回の出力との差分を表示
    if [ -f $PREV_FILE ]; then
        diff $PREV_FILE $CURRENT_FILE | grep -E "^>"
    else
        cat $CURRENT_FILE
    fi

    # 現在の出力を前回の出力として保存
    cp $CURRENT_FILE $PREV_FILE

    # 0.1秒待機
    sleep 0.01
done