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

#define MAX_KVM_INTEL 0xc7000
#define MAX_KVM 0x1b2000
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
    int bitmap_fd = shm_open("afl_bitmap", O_CREAT|O_RDWR, S_IRWXU|S_IRWXG|S_IRWXO);
    if (bitmap_fd == -1)
        perror("open"), exit(1);
    int err = ftruncate(bitmap_fd, 65536);
    if(err == -1){
        perror("ftruncate"), exit(1);
    }
    uint8_t * afl_bitmap = (uint8_t *)mmap(NULL, 65536,
                                    PROT_READ | PROT_WRITE, MAP_SHARED, bitmap_fd, 0);
    if ((void *)afl_bitmap == MAP_FAILED)
        perror("mmap"), exit(1);
    memset(afl_bitmap,0,65536);

    int kvm_intel_fd = shm_open("kvm_intel_coverage", O_CREAT|O_RDWR, S_IRWXU|S_IRWXG|S_IRWXO);
    int kvm_fd = shm_open("kvm_coverage", O_CREAT|O_RDWR, S_IRWXU|S_IRWXG|S_IRWXO);

    if (kvm_intel_fd == -1)
        perror("open"), exit(1);
    err = ftruncate(kvm_intel_fd, MAX_KVM_INTEL);
    if(err == -1){
        perror("ftruncate"), exit(1);
    }

    if (kvm_fd == -1)
        perror("open"), exit(1);
    err = ftruncate(kvm_fd, MAX_KVM);
    if(err == -1){
        perror("ftruncate"), exit(1);
    }

    bool * kvm_intel_coverage = (bool *)mmap(NULL, MAX_KVM_INTEL,
                                    PROT_READ | PROT_WRITE, MAP_SHARED, kvm_intel_fd, 0);
    bool * kvm_coverage = (bool *)mmap(NULL, MAX_KVM,
                                    PROT_READ | PROT_WRITE, MAP_SHARED, kvm_fd, 0);

    if ((void *)kvm_intel_coverage == MAP_FAILED)
        perror("mmap"), exit(1);
    if ((void *)kvm_coverage == MAP_FAILED)
        perror("mmap"), exit(1);

    int prev_kvm_intel_cnt=0;
    int prev_kvm_cnt=0;
    int kvm_intel_cnt=0;
    int kvm_cnt=0;

    // for(int i = 0; i < MAX_KVM_INTEL; i++){
    //     kvm_intel_coverage[i] = 0;
    // }
    for(int i = 0; i < MAX_KVM; i++){
        if(i < MAX_KVM_INTEL)
            prev_kvm_intel_cnt += kvm_intel_coverage[i];
        prev_kvm_cnt += kvm_coverage[i];
        // kvm_intel_coverage[i] = 1;
    }


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
            for(int i = 0; i < MAX_KVM; i++){
                if(i < MAX_KVM_INTEL)
                    kvm_intel_cnt += kvm_intel_coverage[i];
                kvm_cnt += kvm_coverage[i];
                // kvm_intel_coverage[i] = 1;
            }
            if(kvm_cnt > prev_kvm_cnt){
                FILE * total_cov_file = fopen("/home/ishii/nestedFuzz/VMXbench/total_kvm_coverage","w");
                fwrite(kvm_coverage,sizeof(uint8_t),MAX_KVM,total_cov_file);
                fclose(total_cov_file);
                
                // time_t型は基準年からの秒数
                // time_tのままでは使いにくい．time_tはtm構造体に相互に変換できる
                struct timeval tv;
                struct tm *tm;

                gettimeofday(&tv, NULL);

                tm = localtime(&tv.tv_sec);
                char f_name[100];
                sprintf(f_name,"/home/ishii/nestedFuzz/VMXbench/record/n_kvm_%02d_%02d_%02d_%02d_%02d_%06ld",tm->tm_mon+1, tm->tm_mday,\
                tm->tm_hour, tm->tm_min, tm->tm_sec,tv.tv_usec);
                FILE * record = fopen(f_name,"w");
                fwrite(kvm_coverage,sizeof(uint8_t),MAX_KVM,record);
                fclose(record);
            }
            if(kvm_intel_cnt > prev_kvm_intel_cnt){
                FILE * total_cov_file = fopen("/home/ishii/nestedFuzz/VMXbench/total_kvm_intel_coverage","w");
                fwrite(kvm_intel_coverage,sizeof(uint8_t),MAX_KVM_INTEL,total_cov_file);
                fclose(total_cov_file);
                
                // time_t型は基準年からの秒数
                // time_tのままでは使いにくい．time_tはtm構造体に相互に変換できる
                struct timeval tv;
                struct tm *tm;

                gettimeofday(&tv, NULL);

                tm = localtime(&tv.tv_sec);
                char f_name[100];
                sprintf(f_name,"/home/ishii/nestedFuzz/VMXbench/record/n_intel_%02d_%02d_%02d_%02d_%02d_%06ld",tm->tm_mon+1, tm->tm_mday,\
                tm->tm_hour, tm->tm_min, tm->tm_sec,tv.tv_usec);
                FILE * record = fopen(f_name,"w");
                fwrite(kvm_intel_coverage,sizeof(uint8_t),MAX_KVM_INTEL,record);
                fclose(record);
            }
            break;
        }
        usleep(100);
        if(cnt > 10000){
            // kill((pid_t)p[0],SIGKILL);
            // int ret;
            // char *qemu_command = "sudo /home/ishii/nestedFuzz/qemu/build/qemu-system-x86_64 -nodefaults -machine accel=kvm -cpu host -m 128 -bios OVMF.fd -hda 'json:{ \"fat-type\": 0, \"dir\": \"image\", \"driver\": \"vvfat\", \"floppy\": false, \"rw\": true }' -nographic -serial mon:stdio -no-reboot -smp 1";
            // // printf("hello\n");
            // ret = system(qemu_command);
            for(int i = 0; i < MAX_KVM; i++){
                if(i < MAX_KVM_INTEL)
                    kvm_intel_cnt += kvm_intel_coverage[i];
                kvm_cnt += kvm_coverage[i];
                // kvm_intel_coverage[i] = 1;
            }
            if(kvm_cnt > prev_kvm_cnt){
                FILE * total_cov_file = fopen("/home/ishii/nestedFuzz/VMXbench/total_kvm_coverage","w");
                fwrite(kvm_coverage,sizeof(uint8_t),MAX_KVM,total_cov_file);
                fclose(total_cov_file);
                
                // time_t型は基準年からの秒数
                // time_tのままでは使いにくい．time_tはtm構造体に相互に変換できる
                struct timeval tv;
                struct tm *tm;

                gettimeofday(&tv, NULL);

                tm = localtime(&tv.tv_sec);
                char f_name[100];
                sprintf(f_name,"/home/ishii/nestedFuzz/VMXbench/record/n_kvm_%02d_%02d_%02d_%02d_%02d_%06ld",tm->tm_mon+1, tm->tm_mday,\
                tm->tm_hour, tm->tm_min, tm->tm_sec,tv.tv_usec);
                FILE * record = fopen(f_name,"w");
                fwrite(kvm_coverage,sizeof(uint8_t),MAX_KVM,record);
                fclose(record);
            }
            if(kvm_intel_cnt > prev_kvm_intel_cnt){
                FILE * total_cov_file = fopen("/home/ishii/nestedFuzz/VMXbench/total_kvm_intel_coverage","w");
                fwrite(kvm_intel_coverage,sizeof(uint8_t),MAX_KVM_INTEL,total_cov_file);
                fclose(total_cov_file);
                
                // time_t型は基準年からの秒数
                // time_tのままでは使いにくい．time_tはtm構造体に相互に変換できる
                struct timeval tv;
                struct tm *tm;

                gettimeofday(&tv, NULL);

                tm = localtime(&tv.tv_sec);
                char f_name[100];
                sprintf(f_name,"/home/ishii/nestedFuzz/VMXbench/record/n_intel_%02d_%02d_%02d_%02d_%02d_%06ld",tm->tm_mon+1, tm->tm_mday,\
                tm->tm_hour, tm->tm_min, tm->tm_sec,tv.tv_usec);
                FILE * record = fopen(f_name,"w");
                fwrite(kvm_intel_coverage,sizeof(uint8_t),MAX_KVM_INTEL,record);
                fclose(record);
            }

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
    int bitmap_count = 0;
    for (int i = 0; i < 65536; i++){
        if(afl_bitmap[i] != 0)
            bitmap_count +=1;
    }
    if (bitmap_count == 0){
        afl_bitmap[0] =1;
    }
    printf("bitmap_count %d\n", bitmap_count);
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