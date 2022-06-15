#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>
#include <stdlib.h>

#define READ  0
#define WRITE 1

int pipe_c2p[2];
int pipe_p2c[2];
void
do_child()
{
        char    *p[] = {"/bin/echo", "Hello, dad!!", NULL};
        printf("this is child\n");
        close(pipe_c2p[READ]);
        close(pipe_p2c[WRITE]);
        close(1);
        close(0);
        dup2(pipe_p2c[READ], 0);
        dup2(pipe_c2p[WRITE], 1);

        close(pipe_c2p[WRITE]);
        close(pipe_p2c[READ]);
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
        printf("this is parent\n");
        close(pipe_c2p[WRITE]);
        close(pipe_p2c[READ]);
        close(0);
        close(1);
        dup2(pipe_p2c[WRITE], 1);
        dup2(pipe_c2p[READ], 0);
        close(pipe_c2p[READ]);
        close(pipe_p2c[WRITE]);
    char buf[1024];


    while(read(0, buf, sizeof(buf)) <= 0);
//     printf("parent> recv>  %s\n", buf);
        FILE *f = fopen("pa","w");
        // fwrite(buf, sizeof(char), 1024, )/
        fprintf(f, "%s\n",buf);
        fclose(f);
    write(1, "world", 6);
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
}
int main()
{
        int child;
        if (pipe(pipe_c2p) < 0) {
                perror("pipe");
                exit(1);
        }       
        if (pipe(pipe_p2c) < 0) {
                perror("pipe");
                exit(1);
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