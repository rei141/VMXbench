#!/bin/bash

while true; do
    # sudo xl listの出力にmy_vmが含まれているか確認
    output=$(sudo xl list)
    echo "$output"

    # 出力にmy_vmが含まれているか確認
    if ! echo "$output" | grep -q "my_vm"; then
        # my_vmが存在しない場合、xen_disk.shを実行
        ./xen_disk.sh
    fi
    # 1秒待機
    sleep 3
done