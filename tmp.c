#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <stdint.h>
#include <semaphore.h> 
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/shm.h>
// #include <process.h>
#include <sys/mman.h>


int main(int argc, char** argv) {
    int fd = shm_open("ivshmem", O_CREAT|O_RDWR, S_IRWXU|S_IRWXG|S_IRWXO);

    if (fd == -1)
        perror("open"), exit(1);

    uint16_t * ivmshm = (uint16_t *)mmap(NULL, 1024*1024,
                                    PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if ((void *)ivmshm == MAP_FAILED)
        perror("mmap"), exit(1);
    ivmshm += 0x6;

    FILE * input = fopen("afl_input", "rb");
    fread(ivmshm, sizeof(uint16_t), 4096/sizeof(uint16_t), input);
    fclose(input);
    ivmshm[4000] = 1;

    char * arg[] = {"/home/ishii/nestedFuzz/qemu/build/qemu-system-x86_64","-nodefaults",\
    "-object", "memory-backend-file,size=1M,share=on,mem-path=/dev/shm/ivshmem,id=hostmem",
    "-device", "ivshmem-plain,memdev=hostmem",
    "-machine", "accel=kvm", "-cpu", "host", "-m", "512",\
     "-bios" ,"OVMF.fd", "-hda",\
     "json:{ \"fat-type\": 0, \"dir\": \"image\", \"driver\": \"vvfat\", \"floppy\": false, \"rw\": true }", "-nographic" ,"-serial" ,"mon:stdio", "-no-reboot", "-smp", "1",NULL};
    execv("/home/ishii/nestedFuzz/qemu/build/qemu-system-x86_64",arg);

    close(fd);
    if (munmap(ivmshm-6, 1024*1024))
        perror("munmap"), exit(1);
    return 0;
}