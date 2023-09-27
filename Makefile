CC = x86_64-w64-mingw32-gcc
CFLAGS = -std=gnu11 -ffreestanding -shared -nostdlib -Wall -Werror \
	 -fno-stack-check -fno-stack-protector -Wno-unused-variable \
	 -Wno-maybe-uninitialized -Wno-unused-but-set-variable\
	 -mno-stack-arg-probe -mno-red-zone -mno-sse -mno-ms-bitfields \
         -Wl,--subsystem,10 \
         -e EfiMain \

DEFAULT_CONFIG_PATH = ./config.yaml

ifeq ($(CONFIG_PATH),)
    CONFIG_FILE := $(DEFAULT_CONFIG_PATH)
else
    CONFIG_FILE := $(CONFIG_PATH)
endif

QEMU=$(shell python3 ./tools/scripts/get_yaml.py $(CONFIG_FILE) program qemu)
# QEMU = qemu-system-x86_64

QEMU_DISK = 'json:{ "fat-type": 0, "dir": "image", "driver": "vvfat", "floppy": false, "rw": true }'

QEMU_OPTS =-nodefaults -enable-kvm -machine accel=kvm \
	-cpu host,vmx,hv-passthrough=off\
	-m 1024 -smp 2\
    -object memory-backend-file,size=1M,share=on,mem-path=/dev/shm/ivmshm,id=hostmem \
    -device ivshmem-plain,memdev=hostmem \
	-bios OVMF.fd -hda $(QEMU_DISK) -nographic -serial mon:stdio -no-reboot

# QEMU_OPTS =-nodefaults -machine accel=kvm -cpu host -m 128 -bios OVMF.fd -hda $(QEMU_DISK) -nographic -serial mon:stdio -no-reboot

VPATH = src
SRC = src/main.c vmx.c pci.c uefi.c binc.c
main.efi: $(SRC)
	$(CC) $(CFLAGS) $^ -o $@

# %.efi: %.c
# 	$(CC) $(CFLAGS) $< -o $@

.PHONY: all enable_nested disable_nested qemu clean


all: main.efi

qemu: OVMF.fd image/EFI/BOOT/BOOTX64.EFI


OVMF.fd:
	wget http://downloads.sourceforge.net/project/edk2/OVMF/OVMF-X64-r15214.zip
	unzip OVMF-X64-r15214.zip OVMF.fd
	rm OVMF-X64-r15214.zip

image/EFI/BOOT/BOOTX64.EFI: main.efi
	mkdir -p image/EFI/BOOT
	ln -sf ../../../main.efi image/EFI/BOOT/BOOTX64.EFI

clean:
	rm -f main.efi OVMF.fd
	rm -rf image
