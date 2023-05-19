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
#include <signal.h>
// #include <process.h>
#include <sys/mman.h>

#define DEBUG_PRINT(...)     printf("%s(%d) %s:", __FILE__, __LINE__, __func__), printf(__VA_ARGS__)
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

    // uint16_t * ivmshm = (uint16_t *)mmap(NULL, 1024*1024,
    //                                 PROT_READ , MAP_SHARED, fd, 0);
    // uint16_t backup[5000];
    // memcpy(backup, ivmshm, 2*5000);
    // munmap(ivmshm,1024*1024);
    uint16_t * ivmshm = (uint16_t *)mmap(NULL, 1024*1024,
                                    PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if ((void *)ivmshm == MAP_FAILED)
        perror("mmap"), exit(1);
    // memcpy(ivmshm, backup,2*5000);
    ivmshm += 0x6;
    // printf("%x\n",ivmshm[3000]);
    // printf("%x\n", ivmshm);
    // for(int i = 0; i < 20; i++){
    //     printf("buf[%d] = %x\n", i,ivmshm[i]);
    // }
    // shm_unlink("afl_bitmap");


    FILE * input = fopen("afl_input", "rb");
    fread(ivmshm, sizeof(uint16_t), 4096/sizeof(uint16_t), input);
    fclose(input);
    msync(ivmshm,2*5000,MS_ASYNC|MS_SYNC);
    printf("hello\n");

    struct timeval tv;
    struct tm *tm;

    gettimeofday(&tv, NULL);

    tm = localtime(&tv.tv_sec);
    char d_name[200];
    sprintf(d_name,"fuzz_input/%02d_%02d_%02d",tm->tm_mon+1, tm->tm_mday,tm->tm_hour);
    struct stat st;

    if (stat(d_name, &st) != 0) {
        if (mkdir(d_name,
                    S_IRUSR | S_IWUSR | S_IXUSR |
                    S_IRGRP | S_IWGRP | S_IXGRP |
                    S_IROTH | S_IWOTH | S_IXOTH) == 0) {
        } else {
            perror("mkdir");
            return 1;
        }

    }
    
    char f_name[200];
    sprintf(f_name,"fuzz_input/%02d_%02d_%02d/input_%02d_%02d_%02d_%02d_%02d",tm->tm_mon+1, tm->tm_mday,tm->tm_hour,tm->tm_mon+1, tm->tm_mday,\
    tm->tm_hour, tm->tm_min, tm->tm_sec);
    FILE * record = fopen(f_name,"w");
    fwrite(ivmshm,sizeof(uint8_t),4096,record);
    fclose(record);
    
    // sem_post(sem);
    // ivmshm[3000]=0xdead;
    // memcpy(ivmshm,)
// DEBUG_PRINT("\n");
    int bitmap_fd = shm_open("afl_bitmap", O_CREAT|O_RDWR, S_IRWXU|S_IRWXG|S_IRWXO);
    if (bitmap_fd == -1)
        perror("open"), exit(1);
    int err = ftruncate(bitmap_fd, 65536);
    if(err == -1){
        perror("ftruncate"), exit(1);
    }
// DEBUG_PRINT("\n");
    uint8_t * afl_bitmap = (uint8_t *)mmap(NULL, 65536,
                                    PROT_READ | PROT_WRITE, MAP_SHARED, bitmap_fd, 0);
// DEBUG_PRINT("\n");
    if ((void *)afl_bitmap == MAP_FAILED)
        perror("mmap"), exit(1);
// DEBUG_PRINT("\n");
    memset(afl_bitmap,0,65536);

// DEBUG_PRINT("\n");
    // printf("a"); 
    ivmshm[4001] = 0; // write ok
    ivmshm[4000] = 1; // write done
    msync(ivmshm,2*5000,MS_ASYNC|MS_SYNC);

    int qemu_ready = ivmshm[4004]; // qemu_ready
    int cnt=0;
    while(1){
        cnt++;
        if (qemu_ready != 0){
            break;
        }
        usleep(100);
        qemu_ready = ivmshm[4004];
        if(cnt > 70000){
            ivmshm[4000] = 0;
            ivmshm[4002] = 1; // kill qemu
            ivmshm[4004] = 0;
            msync(ivmshm,2*5000,MS_ASYNC|MS_SYNC);
            // sleep(7);
            printf("qemu freeze\n");
            exit(0);
        }
    }

    printf("qemu_ready ok!\n");

    uint16_t flag= ivmshm[4001];

    // printf("hello\n");
    cnt=0;
    while(1){
        cnt++;
        flag = ivmshm[4001];
        if(flag == 1){
            printf("ivmshm[4001] = 1\n");
            break;
        }
        usleep(100);
        if(cnt > 10000){
            // kill((pid_t)p[0],SIGKILL);
            // int ret;
            // char *qemu_command = "sudo /home/ishii/nestedFuzz/qemu/build/qemu-system-x86_64 -nodefaults -machine accel=kvm -cpu host -m 128 -bios OVMF.fd -hda 'json:{ \"fat-type\": 0, \"dir\": \"image\", \"driver\": \"vvfat\", \"floppy\": false, \"rw\": true }' -nographic -serial mon:stdio -no-reboot -smp 1";
            // // printf("hello\n");
            // ret = system(qemu_command);
            ivmshm[4000] = 0;
            ivmshm[4002] = 1; // kill qemu
            ivmshm[4004] = 0;
            msync(ivmshm,2*5000,MS_ASYNC|MS_SYNC);
            // sleep(7);
            break;
        }
    }
    ivmshm[4000] = 0;
    ivmshm[4001] = 0; // write ok
    // ivmshm[4001] = 0;

    // int bitmap_fd = shm_open("afl_bitmap", O_CREAT|O_RDWR, S_IRWXU|S_IRWXG|S_IRWXO);
    // if (bitmap_fd == -1)
    //     perror("open"), exit(1);
    // ftruncate(bitmap_fd, 65536);
    // uint8_t * afl_bitmap = (uint8_t *)mmap(NULL, 65536,
                                    // PROT_READ, MAP_SHARED, bitmap_fd, 0);
    // uint8_t * afl_bitmap = (uint8_t *)mmap(NULL, 65536,
    //                                 PROT_READ | PROT_WRITE, MAP_SHARED, bitmap_fd, 0);
    // if ((void *)afl_bitmap == MAP_FAILED)
    //     perror("mmap"), exit(1);

    if (afl_shm_id_str != NULL) {
        memcpy(afl_area_ptr,afl_bitmap,65536);
        shmdt(afl_area_ptr);
    }
    // if (munmap(afl_bitmap, 65536))
    //     perror("munmap"), exit(1);
    // memset(afl_bitmap,0,65536);
    if (munmap(ivmshm-6, 1024*1024))
        perror("munmap"), exit(1);
    if (munmap(afl_bitmap, 65536))
        perror("munmap"), exit(1);
    close(fd);
    close(bitmap_fd);
    return 0;
}