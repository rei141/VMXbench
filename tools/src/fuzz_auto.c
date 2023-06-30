#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <time.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/time.h>

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
#include "my_yaml.h"
#include "args.h"

uint8_t *kvm_arch_coverage, *kvm_coverage;
path_config_t *path_config;

int create_directory(const char *path) {
    struct stat st;
    if (stat(path, &st) != 0) {
        if (mkdir(path, S_IRWXU | S_IRWXG | S_IRWXO) == 0) {
        } else {
            fprintf(stderr, "mkdir failed\n");
            return 1;
        }
    }

    return 0;
}

int save_input(uint8_t * ivmshm) {
    struct timeval tv;
    struct tm *tm;
    char d_name[192] = {0};
    char f_name[256] = {0};
    struct stat st;
    FILE * fp;

    gettimeofday(&tv, NULL);
    tm = localtime(&tv.tv_sec);

    sprintf(d_name,"%s/%02d_%02d_%02d",path_config->fuzzinput_dir, tm->tm_mon+1, tm->tm_mday,tm->tm_hour);
    if (create_directory(d_name))
        return 1;

    sprintf(f_name,"%s/input_%02d_%02d_%02d_%02d_%02d", d_name, tm->tm_mon+1, tm->tm_mday, tm->tm_hour, tm->tm_min, tm->tm_sec);
    fp = fopen(f_name,"w");
    if (fp == NULL) {
        fprintf(stderr, "fopen failed\n");
        return 1;
    }
    fwrite(ivmshm,sizeof(uint8_t),4096,fp);
    fclose(fp);
    return 0;
}

int save_coverage(uint64_t prev_kvm_arch_cnt, uint64_t prev_kvm_cnt, uint64_t kvm_arch_cnt, uint64_t kvm_cnt) {
    struct timeval tv;
    struct tm *tm;
    char total_cov_path[256] = {0};
    char f_name[256] = {0};
    FILE * total_cov_file;
    FILE * fp;
    if(kvm_cnt > prev_kvm_cnt){
        sprintf(total_cov_path, "%s/total_kvm_coverage", path_config->work_dir);
        total_cov_file = fopen(total_cov_path, "w");
        if (total_cov_file == NULL) {
            fprintf(stderr, "fopen failed\n");
            return 1;
        }
        fwrite(kvm_coverage,sizeof(uint8_t),MAX_KVM,total_cov_file);
        fclose(total_cov_file);

        gettimeofday(&tv, NULL);
        tm = localtime(&tv.tv_sec);
        
        sprintf(f_name,"%s/n_kvm_%02d_%02d_%02d_%02d_%02d_%06ld",path_config->covout_dir,tm->tm_mon+1, tm->tm_mday,\
        tm->tm_hour, tm->tm_min, tm->tm_sec,tv.tv_usec);
        fp = fopen(f_name,"w");
        if (fp == NULL) {
            fprintf(stderr, "fopen failed\n");
            return 1;
        }
        fwrite(kvm_coverage,sizeof(uint8_t),MAX_KVM,fp);
        fclose(fp);
        printf("new coverage file %s\n", f_name);
    }
    if(kvm_arch_cnt > prev_kvm_arch_cnt){
        sprintf(total_cov_path, "%s/total_kvm_arch_coverage", path_config->work_dir);
        total_cov_file = fopen(total_cov_path, "w");
        if (total_cov_file == NULL) {
            fprintf(stderr, "fopen failed\n");
            return 1;
        }
        fwrite(kvm_arch_coverage,sizeof(uint8_t),MAX_KVM_ARCH,total_cov_file);
        fclose(total_cov_file);
        
        gettimeofday(&tv, NULL);
        tm = localtime(&tv.tv_sec);

        sprintf(f_name,"%s/n_arch_%02d_%02d_%02d_%02d_%02d_%06ld",path_config->covout_dir,tm->tm_mon+1, tm->tm_mday,\
        tm->tm_hour, tm->tm_min, tm->tm_sec,tv.tv_usec);
        fp = fopen(f_name,"w");
        if (fp == NULL) {
            fprintf(stderr, "fopen failed\n");
            return 1;
        }
        fwrite(kvm_arch_coverage,sizeof(uint8_t),MAX_KVM_ARCH,fp);
        fclose(fp);
        printf("new coverage file %s\n", f_name);
    }
    return 0;
}

int main(int argc, char** argv) {
    FILE *input_fp;
    int shm_fd, bitmap_fd, kvm_arch_fd, kvm_fd, err;
    uint8_t *ivmshm, *afl_bitmap;
    config_t *config;

    int afl_shm_id;
    const char *afl_shm_id_str = getenv("__AFL_SHM_ID");
    uint8_t *afl_area_ptr = NULL;
    if (afl_shm_id_str != NULL) {
        afl_shm_id = atoi(afl_shm_id_str);
        afl_area_ptr = shmat(afl_shm_id, NULL, 0);
    }
    
    check_cpu_vendor();
    config = create_config(argc, argv);
    if(config == NULL) 
        return 1;
    path_config = parse_config(config->yaml_config_name);
    if (path_config == NULL)
        return 1;

    if (create_directory(path_config->covout_dir))
        return 1;
    if (create_directory(path_config->fuzzinput_dir))
        return 1;
    // printf("qemu_path: %s\n", path_config->qemu_path);
    // printf("work_dir: %s\n", path_config->work_dir);
    // printf("covout_dir: %s\n", path_config->covout_dir);
    // printf("fuzzinput_dir: %s\n", path_config->fuzzinput_dir);
    shm_fd = shm_open(config->shm_name, O_CREAT|O_RDWR, S_IRWXU|S_IRWXG|S_IRWXO);
    if (shm_fd == -1){
        fprintf(stderr, "shm_open failed\n");
        return 1;
    }

    ivmshm = (uint8_t *)mmap(NULL, 1024*1024,
                                    PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
    if ((void *)ivmshm == MAP_FAILED) {
        fprintf(stderr, "mmap failed\n");
        return 1;
    }

    // match the offset position of the address in qemu
    ivmshm += 12;

    input_fp = fopen(config->afl_input_name, "rb");
    if (input_fp == NULL) {
        fprintf(stderr, "fopen failed\n");
        return 1;
    }
    fread(ivmshm, sizeof(uint8_t), 4096, input_fp);
    if (save_input(ivmshm))
        fprintf(stderr, "save_input() failed\n");
        
    fclose(input_fp);

    msync(ivmshm,2*5000,MS_ASYNC|MS_SYNC);
    ivmshm[INPUT_READY] = 1;

    bitmap_fd = shm_open(config->bitmap_name, O_CREAT|O_RDWR, S_IRWXU|S_IRWXG|S_IRWXO);
    if (bitmap_fd == -1) {
        fprintf(stderr, "shm_open failed\n");
        return 1;
    }
    err = ftruncate(bitmap_fd, 65536);
    if(err == -1){
        fprintf(stderr, "ftruncate failed\n");
        return 1;
    }

    afl_bitmap = (uint8_t *)mmap(NULL, 65536,
                                    PROT_READ | PROT_WRITE, MAP_SHARED, bitmap_fd, 0);
    if ((void *)afl_bitmap == MAP_FAILED) {
        fprintf(stderr, "mmap failed\n");
        return 1;
    }
    memset(afl_bitmap,0,65536);

    kvm_arch_fd = shm_open("kvm_arch_coverage", O_CREAT|O_RDWR, S_IRWXU|S_IRWXG|S_IRWXO);
    if (kvm_arch_fd == -1) {
        fprintf(stderr, "shm_open failed\n");
        return 1;
    }
    err = ftruncate(kvm_arch_fd, MAX_KVM_ARCH);
    if(err == -1){
        fprintf(stderr, "ftruncate failed\n");
        return 1;
    }
    kvm_arch_coverage = (uint8_t *)mmap(NULL, MAX_KVM_ARCH,
                                    PROT_READ | PROT_WRITE, MAP_SHARED, kvm_arch_fd, 0);
    if ((void *)kvm_arch_coverage == MAP_FAILED) {
        fprintf(stderr, "mmap failed\n");
        return 1;
    }

    kvm_fd = shm_open("kvm_coverage", O_CREAT|O_RDWR, S_IRWXU|S_IRWXG|S_IRWXO);
    if (kvm_fd == -1) {
        fprintf(stderr, "shm_open failed\n");
        return 1;
    }
    err = ftruncate(kvm_fd, MAX_KVM);
    if(err == -1){
        fprintf(stderr, "ftruncate failed\n");
        return 1;
    }
    kvm_coverage = (uint8_t *)mmap(NULL, MAX_KVM,
                                    PROT_READ | PROT_WRITE, MAP_SHARED, kvm_fd, 0);
    if ((void *)kvm_coverage == MAP_FAILED) {
        fprintf(stderr, "mmap failed\n");
        return 1;        
    }

    uint64_t prev_kvm_arch_cnt=0, prev_kvm_cnt=0, kvm_arch_cnt=0, kvm_cnt=0;
    int max = 0;
    for(int i = 0; i < MAX_KVM; i++){
        if(i < MAX_KVM_ARCH)
            prev_kvm_arch_cnt += kvm_arch_coverage[i];
        prev_kvm_cnt += kvm_coverage[i];
        max++;
    }
    printf("prev : arch_cnt %ld, kvm_cnt %ld\n", prev_kvm_arch_cnt, prev_kvm_cnt);


    msync(ivmshm,2*5000,MS_ASYNC|MS_SYNC);
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
    printf("QEMU ready!\n");

    uint8_t fuzz_done= ivmshm[EXEC_DONE];

    cnt=0;
    int hang = 0;
    while(1){
        cnt++;
        fuzz_done = ivmshm[EXEC_DONE];
        if(fuzz_done != 0){
            printf("Fuzzing done!\n");
            for(int i = 0; i < MAX_KVM; i++){
                if(i < MAX_KVM_ARCH)
                    kvm_arch_cnt += kvm_arch_coverage[i];
                kvm_cnt += kvm_coverage[i];
            }
            printf("arch_cnt %ld, kvm_cnt %ld\n", kvm_arch_cnt, kvm_cnt);
            if (save_coverage(prev_kvm_arch_cnt, prev_kvm_cnt, kvm_arch_cnt, kvm_cnt)) 
                return 1;
            break;
        }
        usleep(100);
        if(cnt > 10000){
            printf("qemu hang\n");
            for(int i = 0; i < MAX_KVM; i++){
                if(i < MAX_KVM_ARCH)
                    kvm_arch_cnt += kvm_arch_coverage[i];
                kvm_cnt += kvm_coverage[i];
            }
            if (save_coverage(prev_kvm_arch_cnt, prev_kvm_cnt, kvm_arch_cnt, kvm_cnt)) 
                return 1;
            ivmshm[QEMU_READY] = 0;
            ivmshm[KILL_QEMU] = 1; // kill qemu
            msync(ivmshm,2*5000,MS_ASYNC|MS_SYNC);
            hang = 1;
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

    if (munmap(ivmshm-12, 1024*1024)) {
        fprintf(stderr, "munmap failed\n");
        return 1;        
    }
    if (munmap(afl_bitmap, 65536)) {
        fprintf(stderr, "munmap failed\n");
        return 1;        
    }
    close(shm_fd);
    close(bitmap_fd);
    free(config);
    free(path_config);

    return 0;
}