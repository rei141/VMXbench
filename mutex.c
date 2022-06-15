#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <semaphore.h>  // sem_wait
#define FILE_MODE (S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH)
sem_t *sem;
void
do_child()
{
        char    *p[] = {"/bin/echo", "Hello, dad!!", NULL};
        printf("this is child\n");
        // sem_wait(sem);

        char buf[1024];
        
        char * arg[] = {"/home/ishii/nestedFuzz/qemu/build/qemu-system-x86_64","-nodefaults", "-machine", "accel=kvm", "-cpu", "host", "-m", "512", "-bios" ,"OVMF.fd", "-hda", "json:{ \"fat-type\": 0, \"dir\": \"image\", \"driver\": \"vvfat\", \"floppy\": false, \"rw\": true }", "-nographic" ,"-serial" ,"mon:stdio", "-no-reboot", "-smp", "1",NULL};

        
        // execv("/bin/echo",p);
        execv("/home/ishii/nestedFuzz/qemu/build/qemu-system-x86_64",arg);
        // printf("child> send> hello\n");

        // while(read(0, buf, sizeof(buf)) <= 0);
        // FILE *f = fopen("chi","w");
        // // fwrite(buf, sizeof(char), 1024, )/
        // fprintf(f, "%s\n",buf);
        // fclose(f);
        // printf("chiled > recv > %s", buf);
        // while (*p)
                // putchar(*p++);
}
void
do_parent()
{
        char    c;
        int     count, status;

    char buf[1024];
        int fd;
        char *s;
        fd = open("/home/ishii/nestedFuzz/VMXbench/shm", O_RDWR);
        if(fd < 0) {
        printf("Error : can't open file\n");
        exit(1);
    }

    // while(shmData[0] == 0){
    //     // printf("hoge\n");
    // }
    // shmData[0] = 0;
    // pthread_mutex_lock(mptr);

    // shmData[1] = 1;
    
    //input与えたら待機
    sem_wait(sem);

//     printf("parent> recv>  %s\n", buf);
        FILE *f = fopen("pa","w");
        // fwrite(buf, sizeof(char), 1024, )/
        // fprintf(f, "%s\n",buf);
        fclose(f);
    sem_post(sem);

//     printf("parent> send> world\n");
        // while ((c = getchar()) != EOF)
        //         putchar(c);
                int ws;
        pid_t pid = -1;
        int options = 0;
    pid_t cid = waitpid(pid,&ws,options);
            if ( cid == -1) {
            perror("wait");
            exit(1);
        }
        // // Detach shred memory
        // if(shmdt( shmData )==-1){
        //     perror("shmdt()");
        // }
    //         if(shmctl(id, IPC_RMID, 0)==-1){
    //     perror("shmctl()");
    //     exit(EXIT_FAILURE);
    // }
}
int main()
{
        int child;
        sem_unlink("/sem");
        sem = sem_open("/sem", O_CREAT, FILE_MODE,1); 
        printf("hello\n");
        sem_wait(sem);
        if ((child = fork()) < 0) {
                perror("fork");
                exit(1);
        }
        if (child)
                do_parent();
        else
                do_child();
        sem_unlink("/sem");
        // sem_destroy(sem); 
        return 0;
}