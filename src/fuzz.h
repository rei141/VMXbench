#pragma once
#include <stddef.h>
#include <stdint.h>

#define APIC_ID        0x20
#define APIC_VERSION   0x30
#define APIC_TPR       0x80
#define APIC_EOI       0xB0
#define APIC_SVR       0xF0
#define APIC_ICR_LOW   0x300
#define APIC_ICR_HIGH  0x310

#define APIC_ENABLE    0x100
#define APIC_FOCUS_DISABLE (1 << 9)

typedef void (*FuncTable)(void);

#define get64b(x) ((uint64_t *)(input_buf + x))[0]
#define get32b(x) ((uint32_t *)(input_buf + x))[0]
#define get16b(x) ((uint16_t *)(input_buf + x))[0]
#define get8b(x) ((uint8_t *)(input_buf + x))[0]

// #define get64b(x) (((uint64_t)genrand_int32() << 32) | genrand_int32())
// #define get32b(x) (uint32_t)genrand_int32()
// #define get16b(x) (uint16_t)(genrand_int32() & 0xFFFF)
// #define get8b(x) (uint8_t)(genrand_int32() & 0xFF)

#define write64b(x, v) ((uint64_t *)(input_buf + x))[0] = (uint64_t)v
#define write32b(x, v) ((uint32_t *)(input_buf + x))[0] = (uint32_t)v
#define write16b(x, v) ((uint16_t *)(input_buf + x))[0] = (uint16_t)v
#define write8b(x, v) ((uint8_t *)(input_buf + x))[0] = (uint8_t)v

extern uint8_t *input_buf;
extern uint64_t index_selector_count;
extern volatile uint64_t *apic_base;
extern FuncTable exec_l1_table[];
extern FuncTable exec_l2_table[];
extern const size_t L1_TABLE_SIZE;
extern const size_t L2_TABLE_SIZE;
void exec_cpuid();
void exec_hlt();
void exec_invd();
void exec_invlpg();
void exec_rdpmc();
void exec_rdtsc();
void exec_rsm();
void exec_vmclear();
void exec_vmlaunch();
void exec_l1_vmptrst();
void exec_l2_vmptrst();
void exec_vmptrld();

void exec_l1_vmread();
void exec_l1_vmwrite();
void exec_l2_vmread();
void exec_l2_vmwrite();
void exec_vmxoff();
void exec_vmxon();
void exec_vmresue();

void exec_cr();
void exec_dr();
void exec_io();

void exec_rdmsr();
void exec_wrmsr();
void exec_mwait();
void exec_monitor();
void exec_pause();
void exec_rdtscp();
void exec_invept();
void exec_invvpid();
void exec_wb();
void exec_xset();
void exec_rdrand();
void exec_invpcid();
void exec_vmfunc();
void exec_encls();
void exec_rdseed();

void exec_pconfig();
void exec_msr_save_load();
void exec_page_table();

uint32_t read_local_apic_id();
uint32_t read_local_apic_version();
void write_eoi();
void write_icr();
void read_icr();
void exec_apic();
void __invpcid(unsigned long pcid, unsigned long addr,
                             unsigned long type);