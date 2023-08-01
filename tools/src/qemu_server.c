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
#include <errno.h>
// #include <process.h>
#include <sys/mman.h>

#include "fuzz.h"
#include "my_yaml.h"
#include "args.h"

int main(int argc, char** argv) {
    int ret;
    int shm_fd, err;
    uint8_t *ivmshm;
    char *name = NULL;

    config_t *config;
    path_config_t *path_config;
    
    config = create_config(argc, argv);
    path_config = parse_config(config->yaml_config_name);
    if (path_config == NULL)
        return 1;
        
    char shm_option[100] = "memory-backend-file,size=1M,share=on,mem-path=/dev/shm/";
    shm_fd = shm_open(config->shm_name, O_CREAT|O_RDWR, S_IRWXU|S_IRWXG|S_IRWXO);
    if (shm_fd == -1){
        fprintf(stderr, "shm_open failed\n");
        return 1;
    }
    err = ftruncate(shm_fd, 1024*1024);
    if(err == -1){
        fprintf(stderr, "ftruncate failed\n");
        return 1;
    }
    strcat(shm_option, config->shm_name);
    strcat(shm_option, ",id=hostmem");

    ivmshm = (uint8_t *)mmap(NULL, 1024*1024,
                                    PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
    if ((void *)ivmshm == MAP_FAILED) {
        fprintf(stderr, "mmap failed\n");
        return 1;
    }
    ivmshm += 12;
    ivmshm[QEMU_READY] = 0;
    ivmshm[KILL_QEMU] = 0;
    msync(ivmshm,2*5000,MS_ASYNC|MS_SYNC);

    char *flags[] = {
        // "hv-vapic=on,hv-evmcs=on,hv-emsr-bitmap=on,hv-enforce-cpuid=on,hv-passthrough=on,hypervisor=off,+x2apic,vmx=on,umip=off,hv_relaxed=on,hv_vpindex=on,hv_time=on"
    // ,"hv-vpindex,hv-synic,hv-tlbflush,hv-ipi,hv-stimer-direct,hv-time,hv-stimer"
    // ,"hv-vapic=on"
    // ,"hv-evmcs=on"
    // ,"hv-emsr-bitmap=on"
    // ,"hv-reset","hv-frequencies,hv-reenlightenment"
    // ,"hv-runtime","hv-crash"
    // ,"hv-avic","hv-relaxed"
    // ,"vmx-vmfunc"
    // ,"hv-passthrough"
    // ,"hv-enforce-cpuid"
    "3dnow","3dnowext","3dnowprefetch","abm","ace2","ace2-en","acpi","adx","aes","amd-no-ssb"
    ,"amd-ssbd","amd-stibp","amx-bf16","amx-int8","amx-tile","apic","arat","arch-capabilities"
    ,"arch-lbr","avic","avx","avx-vnni","avx2","avx512-4fmaps","avx512-4vnniw","avx512-bf16"
    ,"avx512-fp16","avx512-vp2intersect","avx512-vpopcntdq","avx512bitalg","avx512bw","avx512cd"
    ,"avx512dq","avx512er","avx512f","avx512ifma","avx512pf","avx512vbmi","avx512vbmi2","avx512vl"
    ,"avx512vnni","bmi1","bmi2","bus-lock-detect","cid","cldemote","clflush","clflushopt","clwb"
    ,"clzero","cmov","cmp-legacy","core-capability","cr8legacy","cx16","cx8","dca","de","decodeassists"
    ,"ds","ds-cpl","dtes64","erms","est","extapic","f16c","flushbyasid","fma","fma4","fpu","fsgsbase"
    ,"fsrm","full-width-write","fxsr","fxsr-opt","gfni","hle","ht","hypervisor","ia64","ibpb","ibrs"
    ,"ibrs-all","ibs","intel-pt","intel-pt-lip","invpcid","invtsc","kvm-asyncpf","kvm-asyncpf-int"
    ,"kvm-hint-dedicated","kvm-mmu","kvm-msi-ext-dest-id","kvm-nopiodelay","kvm-poll-control"
    ,"kvm-pv-eoi","kvm-pv-ipi","kvm-pv-sched-yield","kvm-pv-tlb-flush","kvm-pv-unhalt","kvm-steal-time"
    ,"kvmclock","kvmclock","kvmclock-stable-bit","la57","lahf-lm","lbrv"
    // ,"lm"
    ,"lwp","mca","mce"
    ,"md-clear","mds-no","misalignsse","mmx","mmxext","monitor","movbe","movdir64b","movdiri"
    ,"mpx"
    ,"msr","mtrr","nodeid-msr","npt","nrip-save","nx","osvw"
    // ,"pae"
    ,"pat","pause-filter"
    ,"pbe","pcid","pclmulqdq","pcommit","pdcm","pdpe1gb","perfctr-core","perfctr-nb","pfthreshold"
    ,"pge","phe","phe-en","pks","pku","pmm","pmm-en","pn","pni","popcnt","pschange-mc-no","pse"
    ,"pse36","rdctl-no","rdpid","rdrand","rdseed","rdtscp","rsba","rtm","sep","serialize","sgx"
    ,"sgx-debug","sgx-exinfo","sgx-kss","sgx-mode64","sgx-provisionkey","sgx-tokenkey","sgx1","sgx2"
    ,"sgxlc","sha-ni","skinit","skip-l1dfl-vmentry","smap","smep","smx","spec-ctrl","split-lock-detect"
    ,"ss","ssb-no","ssbd","sse","sse2","sse4.1","sse4.2","sse4a","ssse3","stibp","svm","svm-lock"
    ,"svme-addr-chk","syscall","taa-no","tbm","tce","tm","tm2","topoext","tsc","tsc-adjust","tsc-deadline"
    ,"tsc-scale","tsx-ctrl","tsx-ldtrk","umip","v-vmsave-vmload","vaes","vgif","virt-ssbd"
    ,"vmcb-clean"
    // ,"vme"
    ,"vmx-activity-hlt","vmx-activity-shutdown","vmx-activity-wait-sipi","vmx-apicv-register"
    // ,"vmx-apicv-vid"
    ,"vmx-apicv-x2apic"
    ,"vmx-apicv-xapic"
    ,"vmx-cr3-load-noexit","vmx-cr3-store-noexit"
    ,"vmx-cr8-load-exit","vmx-cr8-store-exit","vmx-desc-exit","vmx-encls-exit"
    // ,"vmx-entry-ia32e-mode=off,vmx-eptad"
    ,"vmx-entry-load-bndcfgs","vmx-entry-load-efer","vmx-entry-load-pat","vmx-entry-load-perf-global-ctrl"
    ,"vmx-entry-load-pkrs","vmx-entry-load-rtit-ctl","vmx-entry-noload-debugctl"
    // ,"vmx-ept"
    ,"vmx-ept-1gb"
    ,"vmx-ept-2mb","vmx-ept-advanced-exitinfo","vmx-ept-execonly"
    // ,"vmx-eptad=off,vmx-entry-ia32e-mode"
    ,"vmx-eptp-switching"
    // ,"vmx-exit-ack-intr"
    ,"vmx-exit-clear-bndcfgs","vmx-exit-clear-rtit-ctl","vmx-exit-load-efer"
    ,"vmx-exit-load-pat","vmx-exit-load-perf-global-ctrl","vmx-exit-load-pkrs","vmx-exit-nosave-debugctl"
    ,"vmx-exit-save-efer","vmx-exit-save-pat","vmx-exit-save-preemption-timer","vmx-flexpriority"
    ,"vmx-hlt-exit"
    ,"vmx-ins-outs"
    // ,"vmx-intr-exit"
    // ,"vmx-invept"
    ,"vmx-invept-all-context","vmx-invept-single-context"
    ,"vmx-invept-single-context","vmx-invept-single-context-noglobals","vmx-invlpg-exit","vmx-invpcid-exit"
    // ,"vmx-invvpid"
    ,"vmx-invvpid-all-context"
    ,"vmx-invvpid-single-addr"
    ,"vmx-io-bitmap","vmx-io-exit"
    ,"vmx-monitor-exit","vmx-movdr-exit","vmx-msr-bitmap","vmx-mtf","vmx-mwait-exit","vmx-nmi-exit"
    // ,"vmx-page-walk-4"
    ,"vmx-page-walk-5"
    ,"vmx-pause-exit","vmx-ple","vmx-pml","vmx-posted-intr"
    // ,"vmx-preemption-timer"
    ,"vmx-rdpmc-exit"
    ,"vmx-rdrand-exit","vmx-rdseed-exit","vmx-rdtsc-exit"
    ,"vmx-rdtscp-exit"
    // ,"vmx-secondary-ctls"
    ,"vmx-shadow-vmcs"
    ,"vmx-store-lma","vmx-true-ctls","vmx-tsc-offset"
    ,"vmx-tsc-scaling","vmx-unrestricted-guest","vmx-vintr-pending","vmx-vmwrite-vmexit-fields"
    ,"vmx-vnmi"
    ,"vmx-vnmi-pending"
    // ,"vmx-vpid"
    ,"vmx-wbinvd-exit"
    ,"vmx-xsaves","vmx-zero-len-inject","vpclmulqdq"
    ,"waitpkg"
    ,"wbnoinvd"
    ,"wdt"
    ,"xcrypt","xcrypt-en"
    ,"xfd","xgetbv1","xop","xsave","xsavec","xsaveerptr"
    ,"xsaveopt","xsaves","xstore","xstore-en","xtpr"
    ,"vmx-vmfunc"
    ,"x2apic"
    };
    int size = sizeof(flags) / sizeof(flags[0]);

    char *arg2[100] = {NULL};

    arg2[0] = "/usr/sbin/modprobe";
    arg2[1] = "kvm_intel";
    char *flags2[] = {
            "allow_smaller_maxphyaddr"
            ,"emulate_invalid_guest_state"
            ,"enable_apicv"
            ,"enable_ipiv"
            ,"enable_shadow_vmcs"
            ,"enlightened_vmcs"
            ,"ept" // 0224 ubsan
            // ,"ept=0"
            ,"eptad" // 0224 ubsan
            ,"error_on_inconsistent_vmcs_config"
            // ,"nested"
            // ,"nested_early_check"
            ,"unrestricted_guest"
            ,"fasteoi"
            ,"flexpriority"
            ,"vnmi"
            ,"vpid"
            ,"dump_invalid_vmcs"
            ,"sgx"
            ,"pml"
            ,"preemption_timer"
            // ,"vmentry_l1d_flush"
            // ,"ple_window_max"
            // ,"ple_gap"
            // ,"ple_window"
            // ,"ple_window_grow"
            // ,"ple_window_shrink"
            // ,"pt_mode"
            };
    int num_flags = sizeof(flags2) / sizeof(flags2[0]);


    while(1){
        ivmshm[QEMU_READY] = 0;
        pid_t pid;
        int status;
        pid = fork();
        if (pid == 0 ){
            errno = 0;
            pid_t pid1;
            int status1;
            pid1 = fork();
            if(pid1 == 0){
                char *arg1[] = {"/usr/sbin/modprobe","-r", "kvm_intel",NULL};
                for(int i = 0; arg1[i]!= NULL; i++)
                    printf("%s ",arg1[i]);
                printf("\n");
                execv("/usr/sbin/modprobe",arg1); 
                exit(0);
            }
            wait(&status1);
            pid_t pid2;
            int status2;
            int input_ready = 0;
            while(1){
                input_ready = ivmshm[INPUT_READY];
                if (input_ready != 0){
                    // ivmshm[4002] = 0;
                    break; 
                }
    // printf("hello\n");
                usleep(1000*10);
            }

            pid2 = fork();
            if(pid2 == 0){
                char arg_buffers[100][50] = {{0}}; 
                for(int i = 0; i < num_flags; i++){
                    char *flag_value = (ivmshm[1000 + i] % 2) ? "=1" : "=0";
                    snprintf(arg_buffers[i], sizeof(arg_buffers[i]), "%s%s", flags2[i], flag_value);
                    arg2[i + 2] = arg_buffers[i];
                }
                for(int i = 0; arg2[i]!= NULL; i++)
                    printf("%s ",arg2[i]);
                printf("\n");
                execv("/usr/sbin/modprobe",arg2); 
                exit(0);
            }
            wait(&status1);

            char cpu_flags[8192] = "host";
            for(int i = 0; i < 10; i+=1){
                // if(i>=size) break;
                // if(ivmshm[])
                // if(ivmshm[1000+i]%size){
                    strcat(cpu_flags,",");
                    strcat(cpu_flags,flags[ivmshm[1000+i]%size]);
                    // strcat(cpu_flags,flags[i]);
                    strcat(cpu_flags,"=off");
                // }
                // printf("%d\n", i);
            }

            // if(ivmshm[1010]%2){
            //     strcat(cpu_flags,",");
            //     strcat(cpu_flags,"hv-passthrough=off");
            // }
            // else{
                strcat(cpu_flags,",");
                strcat(cpu_flags,"hv-passthrough=on");
                // printf("!!! hv on\n");
            // }
                char * arg[] = {path_config->qemu_path, "afl_bitmap", "-nodefaults", "-enable-kvm",\
                "-machine", "accel=kvm","-cpu", cpu_flags, "-m", "1024", "-smp", "2",\
                "-object", shm_option,\
                "-device", "ivshmem-plain,memdev=hostmem",\
                "-bios" ,"/usr/share/ovmf/OVMF.fd", "-hda",\
                "json:{ \"fat-type\": 0, \"dir\": \"image\", \"driver\": \"vvfat\", \"floppy\": false, \"rw\": true }", "-nographic" ,"-serial" ,"mon:stdio", "-no-reboot",
                NULL};
            if (config->bitmap_name){
                arg[1] = config->bitmap_name;
            }

            ivmshm[QEMU_READY] = 0;
            printf("qemu exec!\n");
            for(int i = 0; arg[i]!= NULL; i++)
                printf("%s ",arg[i]);
            printf("\n");
            execv(path_config->qemu_path, arg);
            exit(1);
        }
        else {
            int flag = 0;
            while(1){
                flag = ivmshm[KILL_QEMU];
                // printf("flag %d\n", flag);
                if (flag == 1){
                    ivmshm[KILL_QEMU] = 0;
                    break; 
                }
                usleep(1000*10);
            }
            ivmshm[QEMU_READY] = 0;
            ret = kill(pid, SIGKILL);
            if (ret == -1) {
                perror("kill");
                // exit(EXIT_FAILURE);
                continue;
            }
            wait(NULL);
        }
    }
    free(config);
    free(path_config);
    return 0;
}