#define MAX_KVM_INTEL 0xc7000
#define MAX_KVM_AMD 0x5f000
#define MAX_KVM 0x1af000

#define INPUT_READY 8000
#define EXEC_DONE 8001
#define KILL_QEMU 8002
#define QEMU_READY 8004
uint64_t max_kvm_arch;

void check_cpu_vendor(void) {
    FILE *cpuinfo = fopen("/proc/cpuinfo", "rb");
    char buffer[255];
    char vendor[16];
    
    if (cpuinfo == NULL) {
        perror("fopen");
        return;
    }

    while (fgets(buffer, 255, cpuinfo)) {
        if (strncmp(buffer, "vendor_id", 9) == 0) {
            sscanf(buffer, "vendor_id : %s", vendor);

            if (strcmp(vendor, "GenuineIntel") == 0) {
                max_kvm_arch = MAX_KVM_INTEL;
            } else if (strcmp(vendor, "AuthenticAMD") == 0) {
                max_kvm_arch = MAX_KVM_AMD;
            } else {
                printf("This is a CPU from another vendor: %s\n", vendor);
                // default value or another value
                max_kvm_arch = 0;
            }

            break;
        }
    }

    fclose(cpuinfo);
}