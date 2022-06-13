#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <stdint.h>
int main(int argc, char** argv)
{
    uint16_t buf[4096/sizeof(uint16_t)];
    int ret = 0;
    // char *qemu_command = "sudo /home/ishii/nestedFuzz/qemu/build/qemu-system-x86_64 -nodefaults -machine accel=kvm -cpu host -m 128 -bios OVMF.fd -hda 'json:{ \"fat-type\": 0, \"dir\": \"image\", \"driver\": \"vvfat\", \"floppy\": false, \"rw\": true }' -nographic -serial mon:stdio -no-reboot -smp 1";

    for(int c = 0; c < 10; c++) {
        ret = system("rm kvm_coverage kvm_intel_coverage -f");
        FILE * f = fopen("image/input","w");
        for(int i =0; i< 4096/sizeof(uint16_t);i++) {
            buf[i] = rand()&0xffff;
        }
        fwrite(buf, sizeof(uint16_t), 4096/sizeof(uint16_t) ,f);
        fclose(f);
        char path[60];
        sprintf(path,"input/random_input_%d",c);
        FILE * fi = fopen(path,"w");
        fwrite(buf, sizeof(uint16_t), 4096/sizeof(uint16_t) ,fi);
        fclose(fi);        
        int ret;
        char * arg[] = {"/home/ishii/nestedFuzz/qemu/build/qemu-system-x86_64","-nodefaults", "-machine", "accel=kvm", "-cpu", "host", "-m", "128", "-bios" ,"OVMF.fd", "-hda", "json:{ \"fat-type\": 0, \"dir\": \"image\", \"driver\": \"vvfat\", \"floppy\": false, \"rw\": true }", "-nographic" ,"-serial" ,"mon:stdio", "-no-reboot", "-smp", "1",NULL};
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
            // printf("hello\n");
        // ret = system(qemu_command);    

        // uint8_t bitmap[65536];

        // char command[50];
        // sprintf(command,"mv image/input bitmap/input_%d -f",c);
        // system(command);

        // sprintf(command,"mv kvm_intel_bitmap bitmap/kvm_bitmap_%d -f",c);
        // system(command);

        // sprintf(command,"mv kvm_intel_coverage bitmap/kvm_coverage_%d -f",c);
        // system(command);

        
        }

    }
    
}
