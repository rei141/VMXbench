#!/bin/bash
set -e
# Compile using the Makefile
make

# Create and mount the image
qemu-img create -f raw vfat_image.img 100M
mkfs.vfat vfat_image.img 
mkdir -p mnt
sudo mount vfat_image.img mnt
sudo cp -Lr image/* mnt/
# sudo cp main.efi mnt/EFI/BOOT/BOOTX64.EFI
sudo umount mnt
sudo xl create my_vm.cfg -c