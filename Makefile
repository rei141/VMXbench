CC = x86_64-w64-mingw32-gcc
CFLAGS = -std=gnu11 -ffreestanding -shared -nostdlib -Wall -Werror \
	 -fno-stack-check -fno-stack-protector -Wno-unused-variable \
	 -Wno-maybe-uninitialized -Wno-unused-but-set-variable\
	 -mno-stack-arg-probe -mno-red-zone -mno-sse -mno-ms-bitfields \
         -Wl,--subsystem,10 \
         -e EfiMain \


QEMU = /home/ishii/nestedFuzz/qemu/build/qemu-system-x86_64
# QEMU = qemu-system-x86_64

QEMU_DISK = 'json:{ "fat-type": 0, "dir": "image", "driver": "vvfat", "floppy": false, "rw": true }'

QEMU_OPTS =-nodefaults -enable-kvm -machine accel=kvm \
	-cpu host,vmx,hv-passthrough=off\
	-m 1024 -smp 2\
    -object memory-backend-file,size=1M,share=on,mem-path=/dev/shm/ivshmem,id=hostmem \
    -device ivshmem-plain,memdev=hostmem \
	-bios OVMF.fd -hda $(QEMU_DISK) -nographic -serial mon:stdio -no-reboot

NESTED=$(shell cat /sys/module/kvm_intel/parameters/nested)
ifeq ($(NESTED),N)
	ENABLE_NESTED=enable_nested
else
	ENABLE_NESTED=
endif

VPATH = src
SRC = main.c vmx.c pci.c uefi.c
main.efi: $(SRC)
	$(CC) $(CFLAGS) $^ -o $@

.PHONY: all enable_nested disable_nested qemu clean


all: main.efi

qemu: OVMF.fd image/EFI/BOOT/BOOTX64.EFI $(ENABLE_NESTED)
	sudo modprobe -r kvm_intel;
	sudo modprobe kvm_intel nested=1 
	# dump_invalid_vmcs=1 enlightened_vmcs=1 pml=1 enable_shadow_vmcs=1 enable_ipiv=1\
	# 	allow_smaller_maxphyaddr=1 preemption_timer=1 sgx=1 unrestricted_guest=1 enable_apicv=1 ept=1 nested_early_check=0;
	sudo $(QEMU) $(QEMU_OPTS)

OVMF.fd:
	wget http://downloads.sourceforge.net/project/edk2/OVMF/OVMF-X64-r15214.zip
	unzip OVMF-X64-r15214.zip OVMF.fd
	rm OVMF-X64-r15214.zip

image/EFI/BOOT/BOOTX64.EFI: main.efi
	mkdir -p image/EFI/BOOT
	ln -sf ../../../main.efi image/EFI/BOOT/BOOTX64.EFI

enable_nested:
	@echo Enabling nested virtualization in KVM ...
	sudo modprobe -r kvm_intel;
	sudo modprobe kvm_intel nested=1;

disable_nested:
	@echo Disabling nested virtualization in KVM ...
	sudo modprobe -r kvm_intel;
	sudo modprobe kvm_intel nested=0;

clean:
	rm -f main.efi OVMF.fd
	rm -rf image
