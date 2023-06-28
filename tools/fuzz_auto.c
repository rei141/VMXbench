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
#include "fuzz.h"

int main(int argc, char** argv) {
    int ret;
    check_cpu_vendor();
    const char *afl_shm_id_str = getenv("__AFL_SHM_ID");
    uint8_t *afl_area_ptr = NULL;
    int afl_shm_id;
    if (afl_shm_id_str != NULL) {
        afl_shm_id = atoi(afl_shm_id_str);
        afl_area_ptr = shmat(afl_shm_id, NULL, 0);
    }
    int fd;
    if (argc > 1 && strstr(argv[1], "ivshmem") != NULL) {
        char *name =  argv[1];
        fd = shm_open(name, O_CREAT|O_RDWR, S_IRWXU|S_IRWXG|S_IRWXO);
    }
    else {
        fd = shm_open("ivshmem", O_CREAT|O_RDWR, S_IRWXU|S_IRWXG|S_IRWXO);
    }


    if (fd == -1)
        perror("open"), exit(1);

    uint8_t * ivmshm = (uint8_t *)mmap(NULL, 1024*1024,
                                    PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if ((void *)ivmshm == MAP_FAILED)
        perror("mmap"), exit(1);
    // for (int j=0; j<16;j++){
    // ivmshm += j;
    // printf(" j = %d\n", j);
    // for(int i = 0; i < 5; i++){
    // // wprintf(L" //")
    // printf("0x%02x\n", ivmshm[i]);
    // }
    // ivmshm -= j;
    // }
    ivmshm += 12;

    ivmshm[9000] = 0xff;
    // printf("ivmshm[9000] = 0x%x\n", ivmshm[9000]);
    // printf("ivmshm[INPUT_READY] = 0x%x\n", ivmshm[INPUT_READY]);

    FILE * input;
    if (argc > 3 && strstr(argv[3], "afl_input") != NULL) {
        char *name =  argv[3];
        input = fopen(name, "rb");
    }
    else {
        input = fopen("afl_input", "rb");
    }

    fread(ivmshm, sizeof(uint8_t), 4096/sizeof(uint8_t), input);
    fclose(input);
    msync(ivmshm,2*5000,MS_ASYNC|MS_SYNC);
    ivmshm[INPUT_READY] = 1;
    struct timeval tv;
    struct tm *tm;

    gettimeofday(&tv, NULL);

    tm = localtime(&tv.tv_sec);
    char d_name[200];
    if (argc > 4) {
        sprintf(d_name,"fuzz_input/%s/%02d_%02d_%02d",argv[4],tm->tm_mon+1, tm->tm_mday,tm->tm_hour);
    }
    else {
        sprintf(d_name,"fuzz_input/%02d_%02d_%02d",tm->tm_mon+1, tm->tm_mday,tm->tm_hour);
    }
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
    if (argc > 4) {
        sprintf(f_name,"fuzz_input/%s/%02d_%02d_%02d/input_%02d_%02d_%02d_%02d_%02d",argv[4],tm->tm_mon+1, tm->tm_mday,tm->tm_hour,tm->tm_mon+1, tm->tm_mday,\
        tm->tm_hour, tm->tm_min, tm->tm_sec);
    }
    else {
        sprintf(f_name,"fuzz_input/%02d_%02d_%02d/input_%02d_%02d_%02d_%02d_%02d",tm->tm_mon+1, tm->tm_mday,tm->tm_hour,tm->tm_mon+1, tm->tm_mday,\
        tm->tm_hour, tm->tm_min, tm->tm_sec);
    }
    FILE * record = fopen(f_name,"w");
    fwrite(ivmshm,sizeof(uint8_t),4096,record);
    fclose(record);
    int bitmap_fd;
    if (argc > 2 && strstr(argv[2], "bitmap") != NULL) {
        char *name = argv[2];
        bitmap_fd = shm_open(name, O_CREAT|O_RDWR, S_IRWXU|S_IRWXG|S_IRWXO);
    }
    else {
        bitmap_fd = shm_open("afl_bitmap", O_CREAT|O_RDWR, S_IRWXU|S_IRWXG|S_IRWXO);
    }
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

    int kvm_arch_fd = shm_open("kvm_arch_coverage", O_CREAT|O_RDWR, S_IRWXU|S_IRWXG|S_IRWXO);
    int kvm_fd = shm_open("kvm_coverage", O_CREAT|O_RDWR, S_IRWXU|S_IRWXG|S_IRWXO);

    if (kvm_arch_fd == -1)
        perror("open"), exit(1);
    err = ftruncate(kvm_arch_fd, MAX_KVM_ARCH);
    if(err == -1){
        perror("ftruncate"), exit(1);
    }

    if (kvm_fd == -1)
        perror("open"), exit(1);
    err = ftruncate(kvm_fd, MAX_KVM);
    if(err == -1){
        perror("ftruncate"), exit(1);
    }

    uint8_t * kvm_arch_coverage = (uint8_t *)mmap(NULL, MAX_KVM_ARCH,
                                    PROT_READ | PROT_WRITE, MAP_SHARED, kvm_arch_fd, 0);
    uint8_t * kvm_coverage = (uint8_t *)mmap(NULL, MAX_KVM,
                                    PROT_READ | PROT_WRITE, MAP_SHARED, kvm_fd, 0);

    if ((void *)kvm_arch_coverage == MAP_FAILED)
        perror("mmap"), exit(1);
    if ((void *)kvm_coverage == MAP_FAILED)
        perror("mmap"), exit(1);

    int prev_kvm_arch_cnt=0;
    int prev_kvm_cnt=0;
    int kvm_arch_cnt=0;
    int kvm_cnt=0;
    int max = 0;
    for(int i = 0; i < MAX_KVM; i++){
        if(i < MAX_KVM_ARCH)
            prev_kvm_arch_cnt += kvm_arch_coverage[i];
        prev_kvm_cnt += kvm_coverage[i];
        max++;
    }
    // printf("max: %d\n ", max);
    printf("prev : arch_cnt %d, kvm_cnt %d\n", prev_kvm_arch_cnt, prev_kvm_cnt);

    // for (int i = 7995; i <8005; i++){
    //     printf("ivmshm[%d] == 0x%x\n", i, ivmshm[i]);
    // }
    msync(ivmshm,2*5000,MS_ASYNC|MS_SYNC);
    // printf("hello\n");
    int qemu_ready = ivmshm[QEMU_READY]; // qemu_ready
    int cnt=0;
    while(1){
        cnt++;
        if (qemu_ready != 0){
            break;
        }
        usleep(100);
        qemu_ready = ivmshm[QEMU_READY];
        if(cnt > 70000){
            ivmshm[INPUT_READY] = 0;
            ivmshm[KILL_QEMU] = 1; // kill qemu
            ivmshm[QEMU_READY] = 0;
            msync(ivmshm,2*5000,MS_ASYNC|MS_SYNC);
            // sleep(7);
            printf("qemu freeze\n");
            exit(0);
        }
    }
    ivmshm[EXEC_DONE] = 0;
    // ivmshm[INPUT_READY] = 1; 
    printf("qemu_ready ok!\n");

    uint8_t fuzz_done= ivmshm[EXEC_DONE];

    // printf("hello\n");
    cnt=0;
    int hang = 0;
    while(1){
        cnt++;
        fuzz_done = ivmshm[EXEC_DONE];
        if(fuzz_done != 0){
            printf("ivmshm[EXEC_DONE] = 1\n");
            printf("hello\n");
            for(int i = 0; i < MAX_KVM; i++){
                if(i < MAX_KVM_ARCH)
                    kvm_arch_cnt += kvm_arch_coverage[i];
                kvm_cnt += kvm_coverage[i];
                
                // kvm_arch_coverage[i] = 1;
            }
            printf("arch_cnt %d, kvm_cnt %d\n", kvm_arch_cnt, kvm_cnt);
            if(kvm_cnt > prev_kvm_cnt){
                FILE * total_cov_file = fopen("total_kvm_coverage","w");
                fwrite(kvm_coverage,sizeof(uint8_t),MAX_KVM,total_cov_file);
                fclose(total_cov_file);

                // time_t型は基準年からの秒数
                // time_tのままでは使いにくい．time_tはtm構造体に相互に変換できる
                struct timeval tv;
                struct tm *tm;

                gettimeofday(&tv, NULL);

                tm = localtime(&tv.tv_sec);
                char f_name[100];
                sprintf(f_name,"record/n_kvm_%02d_%02d_%02d_%02d_%02d_%06ld",tm->tm_mon+1, tm->tm_mday,\
                tm->tm_hour, tm->tm_min, tm->tm_sec,tv.tv_usec);
                FILE * record = fopen(f_name,"w");
                fwrite(kvm_coverage,sizeof(uint8_t),MAX_KVM,record);
                fclose(record);
                printf("new coverage file %s\n", f_name);
            }
            if(kvm_arch_cnt > prev_kvm_arch_cnt){
                FILE * total_cov_file = fopen("total_kvm_arch_coverage","w");
                fwrite(kvm_arch_coverage,sizeof(uint8_t),MAX_KVM_ARCH,total_cov_file);
                fclose(total_cov_file);
                
                // time_t型は基準年からの秒数
                // time_tのままでは使いにくい．time_tはtm構造体に相互に変換できる
                struct timeval tv;
                struct tm *tm;

                gettimeofday(&tv, NULL);

                tm = localtime(&tv.tv_sec);
                char f_name[100];
                sprintf(f_name,"record/n_arch_%02d_%02d_%02d_%02d_%02d_%06ld",tm->tm_mon+1, tm->tm_mday,\
                tm->tm_hour, tm->tm_min, tm->tm_sec,tv.tv_usec);
                FILE * record = fopen(f_name,"w");
                fwrite(kvm_arch_coverage,sizeof(uint8_t),MAX_KVM_ARCH,record);
                fclose(record);
                printf("new coverage file %s\n", f_name);
            }
            break;
        }
        usleep(100);
        if(cnt > 10000){
            // kill((pid_t)p[0],SIGKILL);
            // int ret;
            // char *qemu_command = "sudo /home/ishii/work/qemu/build/qemu-system-x86_64 -nodefaults -machine accel=kvm -cpu host -m 128 -bios OVMF.fd -hda 'json:{ \"fat-type\": 0, \"dir\": \"image\", \"driver\": \"vvfat\", \"floppy\": false, \"rw\": true }' -nographic -serial mon:stdio -no-reboot -smp 1";
            // // printf("hello\n");
            // ret = system(qemu_command);
            for(int i = 0; i < MAX_KVM; i++){
                if(i < MAX_KVM_ARCH)
                    kvm_arch_cnt += kvm_arch_coverage[i];
                kvm_cnt += kvm_coverage[i];
                // kvm_arch_coverage[i] = 1;
            }
            if(kvm_cnt > prev_kvm_cnt){
                FILE * total_cov_file = fopen("total_kvm_coverage","w");
                fwrite(kvm_coverage,sizeof(uint8_t),MAX_KVM,total_cov_file);
                fclose(total_cov_file);
                
                // time_t型は基準年からの秒数
                // time_tのままでは使いにくい．time_tはtm構造体に相互に変換できる
                struct timeval tv;
                struct tm *tm;

                gettimeofday(&tv, NULL);

                tm = localtime(&tv.tv_sec);
                char f_name[100];
                sprintf(f_name,"record/n_kvm_%02d_%02d_%02d_%02d_%02d_%06ld",tm->tm_mon+1, tm->tm_mday,\
                tm->tm_hour, tm->tm_min, tm->tm_sec,tv.tv_usec);
                FILE * record = fopen(f_name,"w");
                fwrite(kvm_coverage,sizeof(uint8_t),MAX_KVM,record);
                fclose(record);
                printf("new coverage file %s\n", f_name);
            }
            if(kvm_arch_cnt > prev_kvm_arch_cnt){
                FILE * total_cov_file = fopen("total_kvm_arch_coverage","w");
                fwrite(kvm_arch_coverage,sizeof(uint8_t),MAX_KVM_ARCH,total_cov_file);
                fclose(total_cov_file);
                struct timeval tv;
                struct tm *tm;
                gettimeofday(&tv, NULL);
                tm = localtime(&tv.tv_sec);
                char f_name[100];
                sprintf(f_name,"record/n_arch_%02d_%02d_%02d_%02d_%02d_%06ld",tm->tm_mon+1, tm->tm_mday,\
                tm->tm_hour, tm->tm_min, tm->tm_sec,tv.tv_usec);
                FILE * record = fopen(f_name,"w");
                fwrite(kvm_arch_coverage,sizeof(uint8_t),MAX_KVM_ARCH,record);
                fclose(record);
                printf("new coverage file %s\n", f_name);
            }
            ivmshm[QEMU_READY] = 0;
            ivmshm[KILL_QEMU] = 1; // kill qemu
            msync(ivmshm,2*5000,MS_ASYNC|MS_SYNC);
            hang = 1;
            // sleep(7);
            break;
        }
    }
    ivmshm[INPUT_READY] = 0;
    ivmshm[EXEC_DONE] = 0; // write ok
    msync(ivmshm,2*5000,MS_ASYNC|MS_SYNC);

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

    if (munmap(ivmshm-12, 1024*1024))
        perror("munmap"), exit(1);
    if (munmap(afl_bitmap, 65536))
        perror("munmap"), exit(1);
    close(fd);
    close(bitmap_fd);
    // if (hang == 1)
    //     exit(1);
    return 0;
}