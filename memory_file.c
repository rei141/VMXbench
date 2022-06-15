#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/shm.h>
    int  id;
    char *shmData;
    char data[1024];
void
do_child()
{
        char    *p[] = {"/bin/echo", "Hello, dad!!", NULL};
        printf("this is child\n");

        char buf[1024];
        
        char * arg[] = {"/home/ishii/nestedFuzz/qemu/build/qemu-system-x86_64","-nodefaults", "-machine", "accel=kvm", "-cpu", "host", "-m", "128", "-bios" ,"OVMF.fd", "-hda", "json:{ \"fat-type\": 0, \"dir\": \"image\", \"driver\": \"vvfat\", \"floppy\": false, \"rw\": true }", "-nographic" ,"-serial" ,"mon:stdio", "-no-reboot", "-smp", "1",NULL};

        
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

    while(shmData[0] == 0){
        // printf("hoge\n");
    }
    shmData[0] = 0;


    shmData[1] = 1;

//     printf("parent> recv>  %s\n", buf);
        FILE *f = fopen("pa","w");
        // fwrite(buf, sizeof(char), 1024, )/
        // fprintf(f, "%s\n",buf);
        fclose(f);

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
        // Detach shred memory
        if(shmdt( shmData )==-1){
            perror("shmdt()");
        }
            if(shmctl(id, IPC_RMID, 0)==-1){
        perror("shmctl()");
        exit(EXIT_FAILURE);
    }
}
int main()
{
        int child;


    // Shared memory create a new with IPC_CREATE
    if((id = shmget(IPC_PRIVATE, 1024, IPC_CREAT|0666)) == -1){
        perror("shmget()");
        exit(-1);
    }
    FILE * fd_shm =  fopen("/home/ishii/nestedFuzz/VMXbench/shmid","wb");
    fwrite(&id, sizeof(int), 1, fd_shm);
    fclose(fd_shm);
    
    // Shared memory attach and convert char address
    if((shmData = (char *)shmat(id, NULL, 0)) == (void *)-1){
        perror("shmat()");
    }
        if ((child = fork()) < 0) {
                perror("fork");
                exit(1);
        }
        if (child)
                do_parent();
        else
                do_child();
        return 0;
}