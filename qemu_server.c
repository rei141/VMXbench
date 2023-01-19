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
// #include <process.h>
#include <sys/mman.h>


int main(int argc, char** argv) {
    int ret;


    int fd = shm_open("ivshmem", O_CREAT|O_RDWR, S_IRWXU|S_IRWXG|S_IRWXO);

    if (fd == -1)
        perror("open"), exit(1);
    int err = ftruncate(fd, 1024*1024);
    if(err == -1){
        perror("ftruncate"), exit(1);
    }

    uint16_t * ivmshm = (uint16_t *)mmap(NULL, 1024*1024,
                                    PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if ((void *)ivmshm == MAP_FAILED)
        perror("mmap"), exit(1);
    ivmshm += 0x6;


    msync(ivmshm,2*5000,MS_ASYNC|MS_SYNC);

    char cpu_flags[4096] = "host,vmx";
    char *flags[] = {"vmx"
    ,"hv-vpindex,hv-synic,hv-tlbflush,hv-ipi,hv-stimer-direct,hv-time,hv-stimer"
    // ,"hv-vapic,hv-evmcs,hv-emsr-bitmap"
    ,"hv-reset","hv-frequencies,hv-reenlightenment"
    ,"hv-runtime","hv-crash"
    ,"hv-avic","hv-relaxed"
    // ,"hv-passthrough"
    ,"hv-enforce-cpuid"
    ,"3dnow","3dnowext","3dnowprefetch","abm","ace2","ace2-en","acpi","adx","aes","amd-no-ssb"
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
    ,"kvmclock","kvmclock","kvmclock-stable-bit","la57","lahf-lm","lbrv","lm","lwp","mca","mce"
    ,"md-clear","mds-no","misalignsse","mmx","mmxext","monitor","movbe","movdir64b","movdiri"
    ,"mpx","msr","mtrr","nodeid-msr","npt","nrip-save","nx","osvw","pae","pat","pause-filter"
    ,"pbe","pcid","pclmulqdq","pcommit","pdcm","pdpe1gb","perfctr-core","perfctr-nb","pfthreshold"
    ,"pge","phe","phe-en","pks","pku","pmm","pmm-en","pn","pni","popcnt","pschange-mc-no","pse"
    ,"pse36","rdctl-no","rdpid","rdrand","rdseed","rdtscp","rsba","rtm","sep","serialize","sgx"
    ,"sgx-debug","sgx-exinfo","sgx-kss","sgx-mode64","sgx-provisionkey","sgx-tokenkey","sgx1","sgx2"
    ,"sgxlc","sha-ni","skinit","skip-l1dfl-vmentry","smap","smep","smx","spec-ctrl","split-lock-detect"
    ,"ss","ssb-no","ssbd","sse","sse2","sse4.1","sse4.2","sse4a","ssse3","stibp","svm","svm-lock"
    ,"svme-addr-chk","syscall","taa-no","tbm","tce","tm","tm2","topoext","tsc","tsc-adjust","tsc-deadline"
    ,"tsc-scale","tsx-ctrl","tsx-ldtrk","umip","v-vmsave-vmload","vaes","vgif","virt-ssbd","vmcb-clean"
    ,"vme","vmx","vmx-activity-hlt","vmx-activity-shutdown","vmx-activity-wait-sipi","vmx-apicv-register"
    ,"vmx-apicv-vid","vmx-apicv-x2apic","vmx-apicv-xapic","vmx-cr3-load-noexit","vmx-cr3-store-noexit"
    ,"vmx-cr8-load-exit","vmx-cr8-store-exit","vmx-desc-exit","vmx-encls-exit","vmx-entry-ia32e-mode"
    ,"vmx-entry-load-bndcfgs","vmx-entry-load-efer","vmx-entry-load-pat","vmx-entry-load-perf-global-ctrl"
    ,"vmx-entry-load-pkrs","vmx-entry-load-rtit-ctl","vmx-entry-noload-debugctl","vmx-ept","vmx-ept-1gb"
    ,"vmx-ept-2mb","vmx-ept-advanced-exitinfo","vmx-ept-execonly","vmx-eptad","vmx-eptp-switching"
    ,"vmx-exit-ack-intr","vmx-exit-clear-bndcfgs","vmx-exit-clear-rtit-ctl","vmx-exit-load-efer"
    ,"vmx-exit-load-pat","vmx-exit-load-perf-global-ctrl","vmx-exit-load-pkrs","vmx-exit-nosave-debugctl"
    ,"vmx-exit-save-efer","vmx-exit-save-pat","vmx-exit-save-preemption-timer","vmx-flexpriority"
    ,"vmx-hlt-exit","vmx-ins-outs","vmx-intr-exit","vmx-invept","vmx-invept-all-context","vmx-invept-single-context"
    ,"vmx-invept-single-context","vmx-invept-single-context-noglobals","vmx-invlpg-exit","vmx-invpcid-exit"
    ,"vmx-invvpid","vmx-invvpid-all-context","vmx-invvpid-single-addr","vmx-io-bitmap","vmx-io-exit"
    ,"vmx-monitor-exit","vmx-movdr-exit","vmx-msr-bitmap","vmx-mtf","vmx-mwait-exit","vmx-nmi-exit"
    ,"vmx-page-walk-4","vmx-page-walk-5","vmx-pause-exit","vmx-ple","vmx-pml","vmx-posted-intr"
    ,"vmx-preemption-timer","vmx-rdpmc-exit","vmx-rdrand-exit","vmx-rdseed-exit","vmx-rdtsc-exit"
    ,"vmx-rdtscp-exit","vmx-secondary-ctls","vmx-shadow-vmcs","vmx-store-lma","vmx-true-ctls","vmx-tsc-offset"
    ,"vmx-tsc-scaling","vmx-unrestricted-guest","vmx-vintr-pending","vmx-vmfunc","vmx-vmwrite-vmexit-fields"
    ,"vmx-vnmi"
    ,"vmx-vnmi-pending"
    ,"vmx-vpid"
    ,"vmx-wbinvd-exit"
    ,"vmx-xsaves","vmx-zero-len-inject","vpclmulqdq"
    ,"waitpkg"
    ,"wbnoinvd"
    ,"wdt"
    ,"+x2apic"
    ,"xcrypt","xcrypt-en"
    ,"xfd","xgetbv1","xop","xsave","xsavec","xsaveerptr"
    ,"xsaveopt","xsaves","xstore","xstore-en","xtpr"
    // char *flags[] = {"3dnow","3dnowext","3dnowprefetch","abm","ace2","ace2-en","acpi","adx","aes","amd-no-ssb","amd-ssbd","amd-stibp","amx-bf16","amx-int8","amx-tile","apic","arat","arch-capabilities","arch-lbr","avic","avx","avx-vnni","avx2","avx512-4fmaps","avx512-4vnniw","avx512-bf16","avx512-fp16","avx512-vp2intersect","avx512-vpopcntdq","avx512bitalg","avx512bw","avx512cd"",","avx512dq","avx512er","avx512f","avx512ifma","avx512pf","avx512vbmi","avx512vbmi2","avx512vl","avx512vnni","bmi1","bmi2","bus-lock-detect","cid","cldemote","clflush","clflushopt","clwb","clzero","cmov","cmp-legacy","core-capability","cr8legacy","cx16","cx8","dca","de","decodeassists","ds","ds-cpl","dtes64","erms","est","extapic","f16c","flushbyasid","fma","fma4","fpu","fsgsbase","fsrm","full-width-write","fxsr","fxsr-opt","gfni","hle","ht","hypervisor","ia64","ibpb","ibrs","ibrs-all","ibs","intel-pt","intel-pt-lip","invpcid","invtsc","kvm-asyncpf","kvm-asyncpf-int","kvm-hint-dedicated","kvm-mmu","kvm-msi-ext-dest-id","kvm-nopiodelay","kvm-poll-control","kvm-pv-eoi","kvm-pv-ipi","kvm-pv-sched-yield","kvm-pv-tlb-flush","kvm-pv-unhalt","kvm-steal-time","kvmclock","kvmclock","kvmclock-stable-bit","la57","lahf-lm","lbrv","lm","lwp","mca","mce","md-clear","mds-no","misalignsse","mmx","mmxext","monitor","movbe","movdir64b","movdiri","mpx","msr","mtrr","nodeid-msr","npt","nrip-save","nx","osvw","pae","pat","pause-filter","pbe","pcid","pclmulqdq","pcommit","pdcm","pdpe1gb","perfctr-core","perfctr-nb","pfthreshold","pge","phe","phe-en","pks","pku","pmm","pmm-en","pn","pni","popcnt","pschange-mc-no","pse","pse36","rdctl-no","rdpid","rdrand","rdseed","rdtscp","rsba","rtm","sep","serialize","sgx","sgx-debug","sgx-exinfo","sgx-kss","sgx-mode64","sgx-provisionkey","sgx-tokenkey","sgx1","sgx2","sgxlc","sha-ni","skinit","skip-l1dfl-vmentry","smap","smep","smx","spec-ctrl","split-lock-detect","ss","ssb-no","ssbd","sse","sse2","sse4.1","sse4.2","sse4a","ssse3","stibp","svm","svm-lock","svme-addr-chk","syscall","taa-no","tbm","tce","tm","tm2","topoext","tsc","tsc-adjust","tsc-deadline","tsc-scale","tsx-ctrl","tsx-ldtrk","umip","v-vmsave-vmload","vaes","vgif","virt-ssbd","vmcb-clean","vme","vmx","vmx-activity-hlt","vmx-activity-shutdown","vmx-activity-wait-sipi","vmx-apicv-register","vmx-apicv-vid","vmx-apicv-x2apic","vmx-apicv-xapic","vmx-cr3-load-noexit","vmx-cr3-store-noexit","vmx-cr8-load-exit","vmx-cr8-store-exit","vmx-desc-exit","vmx-encls-exit","vmx-entry-ia32e-mode","vmx-entry-load-bndcfgs","vmx-entry-load-efer","vmx-entry-load-pat","vmx-entry-load-perf-global-ctrl","vmx-entry-load-pkrs","vmx-entry-load-rtit-ctl","vmx-entry-noload-debugctl","vmx-ept","vmx-ept-1gb","vmx-ept-2mb","vmx-ept-advanced-exitinfo","vmx-ept-execonly","vmx-eptad","vmx-eptp-switching","vmx-exit-ack-intr","vmx-exit-clear-bndcfgs","vmx-exit-clear-rtit-ctl","vmx-exit-load-efer","vmx-exit-load-pat","vmx-exit-load-perf-global-ctrl","vmx-exit-load-pkrs","vmx-exit-nosave-debugctl","vmx-exit-save-efer","vmx-exit-save-pat","vmx-exit-save-preemption-timer","vmx-flexpriority","vmx-hlt-exit","vmx-ins-outs","vmx-intr-exit","vmx-invept","vmx-invept-all-context","vmx-invept-single-context","vmx-invept-single-context","vmx-invept-single-context-noglobals","vmx-invlpg-exit","vmx-invpcid-exit","vmx-invvpid","vmx-invvpid-all-context","vmx-invvpid-single-addr","vmx-io-bitmap","vmx-io-exit","vmx-monitor-exit","vmx-movdr-exit","vmx-msr-bitmap","vmx-mtf","vmx-mwait-exit","vmx-nmi-exit","vmx-page-walk-4","vmx-page-walk-5","vmx-pause-exit","vmx-ple","vmx-pml","vmx-posted-intr","vmx-preemption-timer","vmx-rdpmc-exit","vmx-rdrand-exit","vmx-rdseed-exit","vmx-rdtsc-exit","vmx-rdtscp-exit","vmx-secondary-ctls","vmx-shadow-vmcs","vmx-store-lma","vmx-true-ctls","vmx-tsc-offset","vmx-tsc-scaling","vmx-unrestricted-guest","vmx-vintr-pending","vmx-vmfunc","vmx-vmwrite-vmexit-fields","vmx-vnmi","vmx-vnmi-pending","vmx-vpid","vmx-wbinvd-exit","vmx-xsaves","vmx-zero-len-inject","vpclmulqdq","waitpkg","wbnoinvd","wdt","x2apic","xcrypt","xcrypt-en","xfd","xgetbv1","xop","xsave","xsavec","xsaveerptr","xsaveopt","xsaves","xstore","xstore-en","xtpr",
    ,NULL};
    // host,+x2apic,vmx=on
    for(int i = 0; flags[i]; i++){
        strcat(cpu_flags,",");
        strcat(cpu_flags,flags[i]);
        // printf("%d\n", i);
    }
    // char cpu_flags[4096] = "host,+x2apic,vmx=on";

    char * arg[] = {"/home/ishii/nestedFuzz/qemu/build/qemu-system-x86_64","-nodefaults",\
    "-object", "memory-backend-file,size=1M,share=on,mem-path=/dev/shm/ivshmem,id=hostmem",
    "-device", "ivshmem-plain,memdev=hostmem",
    "-machine", "accel=kvm","-cpu", cpu_flags, "-m", "512",\
     "-bios" ,"OVMF.fd", "-hda",\
     "json:{ \"fat-type\": 0, \"dir\": \"image\", \"driver\": \"vvfat\", \"floppy\": false, \"rw\": true }", "-nographic" ,"-serial" ,"mon:stdio", "-no-reboot", "-smp", "1",
     NULL};
    //  host,3dnow,hv_relaxed,hv_vpindex,hv_time,hv-vapic,hv-evmcs,hv-enforce-cpuid
    ivmshm[4002] = 0;
    msync(ivmshm,2*5000,MS_ASYNC|MS_SYNC);
    while(1){
        pid_t pid;
        int status;
        pid = fork();
        if (pid == 0 ){
            char *arg1[] = {"modprobe","-r", "kvm_intel"};
            char *arg2[] = {"modprobe","kvm_intel", "nested=1 dump_invalid_vmcs=1 enlightened_vmcs=1 pml=1 enable_shadow_vmcs=1 allow_smaller_maxphyaddr=1 preemption_timer=1"};
	        execv("modprobe",arg1); 
	        execv("modprobe",arg2); 
            execv("/home/ishii/nestedFuzz/qemu/build/qemu-system-x86_64",arg);
            exit(1);
        }
        else {
            int flag = 0;
            while(1){
                flag = ivmshm[4002];
                // printf("flag %d\n", flag);
                if (flag == 1){
                    ivmshm[4002] = 0;
                    break; 
                }
                usleep(1000*10);
            }
            ret = kill(pid, SIGKILL);
            wait(NULL);
            // if (ret == -1) {
            //     perror("kill");
            //     exit(EXIT_FAILURE);
            // }
        }
    }

    return 0;
}