#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <stdint.h>
#include <semaphore.h> 
#include <sys/stat.h>
#include <fcntl.h>
// #include <process.h>
#include <sys/mman.h>

#define FILE_MODE (S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH)
int main(int argc, char** argv) {
    int ret;
    char *qemu_command = "/home/ishii/nestedFuzz/qemu/build/qemu-system-x86_64 -nodefaults -machine accel=kvm -cpu host -m 128 -bios OVMF.fd -hda 'json:{ \"fat-type\": 0, \"dir\": \"image\", \"driver\": \"vvfat\", \"floppy\": false, \"rw\": true }' -nographic -serial mon:stdio -no-reboot -smp 1";
    // printf("hello\n");
    // char copy[100];
    const char *afl_shm_id_str = getenv("__AFL_SHM_ID");
    if (afl_shm_id_str != NULL) {
        FILE * f = fopen("hoge","w");
        fclose(f);
    }
    // sem_t *sem;
    // sem_unlink("/sem");
    // sem = sem_open("/sem", O_CREAT, FILE_MODE,0); 
    // sem_wait(sem);
    // printf("hello\n");
    struct tm tm;
    char rm1[100];
    char * arg[] = {"/home/ishii/nestedFuzz/qemu/build/qemu-system-x86_64","-nodefaults",\
    "-object", "memory-backend-file,size=1M,share=on,mem-path=/dev/shm/ivshmem,id=hostmem",
    "-device", "ivshmem-plain,memdev=hostmem",
    "-machine", "accel=kvm", "-cpu", "host", "-m", "512",\
     "-bios" ,"OVMF.fd", "-hda",\
     "json:{ \"fat-type\": 0, \"dir\": \"image\", \"driver\": \"vvfat\", \"floppy\": false, \"rw\": true }", "-nographic" ,"-serial" ,"mon:stdio", "-no-reboot", "-smp", "1",NULL};
    
    ret = system("rm kvm_coverage kvm_intel_coverage -f");
    // execlp("sh","sh",qemu_command,NULL);
    struct stat stat;
    int fd = shm_open("ivshmem", O_CREAT|O_RDWR, S_IRWXU|S_IRWXG|S_IRWXO);
    if (fd == -1)
        perror("open"), exit(1);
    // fstat(fd, &stat);
    // printf("%lx\n",stat.st_dev);
        /* Mmap buffer shared between kernel- and user-space. */
    ftruncate(fd, 1024*1024);
    uint16_t * ivmshm = (unsigned long *)mmap(NULL, 1024*1024,
                                    PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if ((void *)ivmshm == MAP_FAILED)
        perror("mmap"), exit(1);
    for(int i = 0; i<100;i++){
        ivmshm[i] =0xffff;
    }

    // if (munmap(ivmshm, 1024*1024))
    //     perror("munmap"), exit(1);
    // close(fd);
    // return 0;

    execv("/home/ishii/nestedFuzz/qemu/build/qemu-system-x86_64",arg);
    uint16_t buf[4096/sizeof(uint16_t)];

    // int n = read(0, buf,sizeof(buf));

    FILE * in = fopen("input/random_input", "rb");

    fread(buf, sizeof(uint16_t), 4096/sizeof(uint16_t),in);
    fclose(in);

    FILE * input = fopen("image/input", "w");
    fwrite(buf, sizeof(uint16_t), 4096/sizeof(uint16_t), input);
    fclose(input);

    // ret = system(qemu_command);
    pid_t pid;
    int status;
    pid = fork();
    if (pid == 0 ){
        execv("/home/ishii/nestedFuzz/qemu/build/qemu-system-x86_64",arg);
        // execlp("sh","sh",qemu_command,NULL);
        exit(1);
    }
    else {
        int ws;
        pid_t pid = -1;
        int options = 0;
        pid_t cid = waitpid(pid,&ws,options);
        if ( cid == -1) {
            perror("wait");
            exit(1);
        }
        
        // ret = system(qemu_command);
        // kirokuyouni kopi******************************************8
        // time_t t = time(NULL);
        // localtime_r(&t, &tm);
        // char copy[100];
        // sprintf(copy,"cp image/input log_input/input_%02d_%02d_%02d_%02d_%02d -f",tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
        // ret = system(copy);
        // char mv1[100];
        // sprintf(copy,"cp kvm_intel_coverage log_input/coverage_%02d_%02d_%02d_%02d_%02d -f",tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
        // ret = system(copy);    

        // char mv2[100];
        // sprintf(copy,"cp kvm_intel_bitmap log_input/bitmap_%02d_%02d_%02d_%02d_%02d -f",tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
        // ret = system(copy);  
    }

    return 0;
}