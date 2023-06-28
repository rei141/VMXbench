#include <stdio.h>
#include <stdbool.h>
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
#include <signal.h>
// #include <process.h>
#include <sys/mman.h>
#include "vmx.h"

#define VMCS_READY 8005
uint8_t *input_buf;
int vmcs_num = 153;
uint16_t vmcs_index[] = {0x0000, 0x0002, 0x0004, 0x0800, 0x0802, 0x0804, 0x0806, 0x0808, 0x080a, 0x080c, 0x080e, 0x0810,
                         0x0812, 0x0c00, 0x0c02, 0x0c04, 0x0c06, 0x0c08, 0x0c0a, 0x0c0c, 0x2000, 0x2002, 0x2004, 0x2006, 0x2008, 0x200a, 0x200c,
                         0x200e, 0x2010, 0x2012, 0x2014, 0x2016, 0x2018, 0x201a, 0x201c, 0x201e, 0x2020, 0x2022, 0x2024, 0x2028, 0x202a, 0x202c,
                         0x202e, 0x2032, 0x2400, 0x2800, 0x2802, 0x2804, 0x2806, 0x2808, 0x280a, 0x280c, 0x280e, 0x2810, 0x2c00, 0x2c02, 0x2c04,
                         0x4000, 0x4002, 0x4004, 0x4006, 0x4008, 0x400a, 0x400c, 0x400e, 0x4010, 0x4012, 0x4014, 0x4016, 0x4018, 0x401a, 0x401c,
                         0x401e, 0x4020, 0x4022, 0x4400, 0x4402, 0x4404, 0x4406, 0x4408, 0x440a, 0x440c, 0x440e, 0x4800, 0x4802, 0x4804, 0x4806, 0x4808,
                         0x480a, 0x480c, 0x480e, 0x4810, 0x4812, 0x4814, 0x4816, 0x4818, 0x481a, 0x481c, 0x481e, 0x4820, 0x4822, 0x4824, 0x4826,
                         0x4828, 0x482a, 0x482e, 0x4c00, 0x6000, 0x6002, 0x6004, 0x6006, 0x6008, 0x600a, 0x600c, 0x600e, 0x6400, 0x6404, 0x6402,
                         0x6408, 0x6406, 0x640a, 0x6800, 0x6802, 0x6804, 0x6806, 0x6808, 0x680a, 0x680c, 0x680e, 0x6810, 0x6812, 0x6814, 0x6816,
                         0x6818, 0x681a, 0x681c, 0x681e, 0x6820, 0x6822, 0x6824, 0x6826, 0x6c00, 0x6c02, 0x6c04, 0x6c06, 0x6c08, 0x6c0a, 0x6c0c,
                         0x6c0e, 0x6c10, 0x6c12, 0x6c14, 0x6c16};

int main(void) {
    int fd;

    fd = shm_open("ivshmem", O_CREAT|O_RDWR, S_IRWXU|S_IRWXG|S_IRWXO);


    if (fd == -1)
        perror("open"), exit(1);

    input_buf = (uint8_t *)mmap(NULL, 1024*1024,
                                    PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if ((void *)input_buf == MAP_FAILED)
        perror("mmap"), exit(1);

    input_buf += 12;
    int vmcs_ready = input_buf[VMCS_READY];
    while (vmcs_ready != 1) {
        vmcs_ready = input_buf[VMCS_READY];
    }
    // printf("0x%lx\n", input_buf);
    input_buf += 0x3000;
    // printf("%d\n", VMCS_HOST_RIP);
    for (int i = 0; i < vmcs_num; i++){
        uint64_t v = vmread(i);
        // printf("%d: 0x%lx\n", i, v);
    }
    for (int i = 0; i < 18; i++){
        uint64_t v = rdmsr(i);
        // printf("%d: 0x%lx\n", i, v);
    }
        enum VMX_error_code vmentry_check_failed = VMenterLoadCheckVmControls();
        if (!vmentry_check_failed)
        {
            printf("VMX CONTROLS OK!\r\n");
        }
        else
        {
            printf("VMX CONTROLS ERROR %0d\r\n", vmentry_check_failed);
        }
        vmentry_check_failed = VMenterLoadCheckHostState();
        if (!vmentry_check_failed)
        {
            printf("HOST STATE OK!\r\n");
        }
        else
        {
            printf("HOST STATE ERROR %0d\r\n", vmentry_check_failed);
        }
        uint64_t qualification;
        // printf("hello\n");
        uint32_t is_error = VMenterLoadCheckGuestState(&qualification);
        // printf("hello\n");
        if (!is_error)
        {
            printf("GUEST STATE OK!\r\n");
        }
        else
        {
            printf("GUEST STATE ERROR %0d\r\n", qualification);
            printf("GUEST STATE ERROR %0d\r\n", is_error);
        }

    input_buf -= 0x3000;
    input_buf[VMCS_READY] = 0;

    if (munmap(input_buf-12, 1024*1024))
        perror("munmap"), exit(1);
    return 0;
}