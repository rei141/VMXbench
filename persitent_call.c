#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <stdint.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <limits.h>
#include <sys/stat.h>
#include <semaphore.h> 
#include <fcntl.h>
// #include <process.h>
#define FILE_MODE (S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH)

#pragma clang optimize off
#pragma GCC            optimize("O0")

int main(int argc, char** argv) {
    __AFL_INIT();
    int ret;
    char *qemu_command = "/home/ishii/nestedFuzz/qemu/build/qemu-system-x86_64 -nodefaults -machine accel=kvm -cpu host -m 128 -bios OVMF.fd -hda 'json:{ \"fat-type\": 0, \"dir\": \"image\", \"driver\": \"vvfat\", \"floppy\": false, \"rw\": true }' -nographic -serial mon:stdio -no-reboot -smp 1";
    char * arg[] = {"/home/ishii/nestedFuzz/qemu/build/qemu-system-x86_64","-nodefaults", "-machine", "accel=kvm", "-cpu", "host", "-m", "128", "-bios" ,"OVMF.fd", "-hda", "json:{ \"fat-type\": 0, \"dir\": \"image\", \"driver\": \"vvfat\", \"floppy\": false, \"rw\": true }", "-nographic" ,"-serial" ,"mon:stdio", "-no-reboot", "-smp", "1",NULL};
    // printf("hello\n");
    char copy[100];
    const char *afl_shm_id_str = getenv("__AFL_SHM_ID");
    sem_t *sem;
    sem_unlink("/sem");
    sem = sem_open("/sem", O_CREAT, FILE_MODE,1); 
    // printf("hello\n");
    sem_wait(sem);

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
        while (__AFL_LOOP(10000)) {
            sem_wait(sem);
            ret = system("rm kvm_coverage kvm_intel_coverage -f");
            uint16_t buf[4096/sizeof(uint16_t)];
            FILE * afl_input = fopen("./afl_input", "rb");

            int n = fread(0, buf,sizeof(buf),afl_input);
            fclose(afl_input);
            
            FILE * input = fopen("image/input", "w");
            fwrite(buf, sizeof(uint16_t), 4096/sizeof(uint16_t), input);
            fclose(input);
            sem_post(sem);
            usleep(500000);
        }
        pid_t cid = waitpid(pid,&ws,options);
        if ( cid == -1) {
            perror("wait");
            exit(1);
        }
    }

    return 0;
}