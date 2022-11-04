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
    int ret;

    const char *afl_shm_id_str = getenv("__AFL_SHM_ID");
    uint8_t *afl_area_ptr = NULL;
    int afl_shm_id;
    if (afl_shm_id_str != NULL) {
        afl_shm_id = atoi(afl_shm_id_str);
        afl_area_ptr = shmat(afl_shm_id, NULL, 0);
    }

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


    int bitmap_fd = shm_open("afl_bitmap", O_CREAT|O_RDWR, S_IRWXU|S_IRWXG|S_IRWXO);
    if (bitmap_fd == -1)
        perror("open"), exit(1);
    uint8_t * afl_bitmap = (uint8_t *)mmap(NULL, 65536,
                                    PROT_READ | PROT_WRITE, MAP_SHARED, bitmap_fd, 0);
    if ((void *)afl_bitmap == MAP_FAILED)
        perror("mmap"), exit(1);
    memset(afl_bitmap,0,65536);


    ivmshm[4000] = 1;
    msync(ivmshm,2*5000,MS_ASYNC|MS_SYNC);
    // printf("a");
    uint16_t flag= ivmshm[4001];
        while(1){
            flag = ivmshm[4001];
            usleep(100);
            if(flag == 1){
                break;
            }
        }
    ivmshm[4001] = 0;
    
    int ret;
    char *qemu_command = "sudo /home/ishii/work/qemu/qemu-system-x86_64 -nodefaults -machine accel=kvm -cpu host -m 128 -bios OVMF.fd -hda 'json:{ \"fat-type\": 0, \"dir\": \"image\", \"driver\": \"vvfat\", \"floppy\": false, \"rw\": true }' -nographic -serial mon:stdio -no-reboot -smp 1";
    // printf("hello\n");
    ret = system(qemu_command);


    if (afl_shm_id_str != NULL) {
    memcpy(afl_area_ptr,afl_bitmap,65536);
    shmdt(afl_area_ptr);
    }
    // if (munmap(afl_bitmap, 65536))
    //     perror("munmap"), exit(1);
    // memset(afl_bitmap,0,65536);
    close(fd);
    close(bitmap_fd);
    if (munmap(ivmshm-6, 1024*1024))
        perror("munmap"), exit(1);
    if (munmap(afl_bitmap, 65536))
        perror("munmap"), exit(1);
    return 0;
}