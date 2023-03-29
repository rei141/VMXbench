/******************************************************************************

  The MIT License (MIT)

  Copyright (c) 2017 Takahiro Shinagawa (The University of Tokyo)

  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in
  all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
  THE SOFTWARE.

******************************************************************************/

/** ***************************************************************************
 * @file main.c
 * @brief The VMX benchmark (VMXbench)
 * @copyright Copyright (c) 2017 Takahiro Shinagawa (The University of Tokyo)
 * @license The MIT License (http://opensource.org/licenses/MIT)
 *************************************************************************** */

#include <stdint.h>
#include <stdbool.h>
#include "pci.h"
#include "vmx.h"
#include "uefi.h"

extern EFI_SYSTEM_TABLE *SystemTable;

extern uint64_t vmxonptr;

static int env[28];

uint16_t vmcs_index[] = {0x0000, 0x0002, 0x0004, 0x0800, 0x0802, 0x0804, 0x0806, 0x0808, 0x080a, 0x080c, 0x080e, 0x0810,
                         0x0812, 0x0c00, 0x0c02, 0x0c04, 0x0c06, 0x0c08, 0x0c0a, 0x0c0c, 0x2000, 0x2002, 0x2004, 0x2006, 0x2008, 0x200a, 0x200c,
                         0x200e, 0x2010, 0x2012, 0x2014, 0x2016, 0x2018, 0x201a, 0x201c, 0x201e, 0x2020, 0x2022, 0x2024, 0x2028, 0x202a, 0x202c,
                         0x202e, 0x2032, 0x2400, 0x2800, 0x2802, 0x2804, 0x2806, 0x2808, 0x280a, 0x280c, 0x280e, 0x2810, 0x2c00, 0x2c02, 0x2c04,
                         0x4000, 0x4002, 0x4004, 0x4006, 0x4008, 0x400a, 0x400c, 0x400e, 0x4010, 0x4012, 0x4014, 0x4016, 0x4018, 0x401a, 0x401c,
                         0x401e, 0x4020, 0x4022, 0x4400, 0x4402, 0x4404, 0x4406, 0x4408, 0x440a, 0x440c, 0x440e, 0x4800, 0x4802, 0x4804, 0x4806, 0x4808,
                         0x480a, 0x480c, 0x480e, 0x4810, 0x4812, 0x4814, 0x4816, 0x4818, 0x481a, 0x481c, 0x481e, 0x4820, 0x4822, 0x4824, 0x4826,
                         0x4828, 0x482a, 0x482e, 0x4c00, 0x6000, 0x6002, 0x6004, 0x6006, 0x6008, 0x600a, 0x600c, 0x600e, 0x6400, 0x6404, 0x6402,
                         0x6408, 0x6406, 0x640a, 0x6800, 0x6802, 0x6804, 0x6806, 0x6808, 0x680a, 0x680c, 0x680e, 0x6810, 0x6812, 0x6814, 0x6816,
                         0x6818, 0x681a, 0x681c, 0x681e, 0x6820, 0x6822, 0x6824, 0x6826, 0x6c00, 0x6c02, 0x6c04, 0x6c06, 0x6c08, 0x6c0a, 0x6c0c,
                         0x6c0e, 0x6c10, 0x6c12, 0x6c14, 0x6c16};

#define vmcs_num 153
#define get64b(x) ((uint64_t *)(input_buf + x))[0]
#define get32b(x) ((uint32_t *)(input_buf + x))[0]
uint16_t l = 54;
uint16_t shiftcount;
uint16_t *input_buf;
uint64_t restore_vmcs[vmcs_num];
char vmcs[4096] __attribute__((aligned(4096)));
char vmcs_backup[4096] __attribute__((aligned(4096)));
char shadow_vmcs[4096] __attribute__((aligned(4096)));
char shadow_vmcs2[4096] __attribute__((aligned(4096)));
char vmxon_region[4096] __attribute__((aligned(4096)));

uint64_t msr_load[1024] __attribute__((aligned(4096)));
uint64_t msr_store[1024] __attribute__((aligned(4096)));
uint64_t vmentry_msr_load[1024] __attribute__((aligned(4096)));

uint32_t revision_id;
uint32_t guest_hang;
uint64_t loop_count;
uint64_t prev_val;
uint64_t next_val;
uint64_t prev_ind;
uint64_t index_count;

void print_exitreason(uint64_t reason)
{
    uint64_t q = vmread(0x6400);
    uint64_t rip = vmread(0x681E);
    uint64_t rsp = vmread(0x681C);
    wprintf(L"Unexpected VM exit: reason=%x, qualification=%x\r\n", reason, q);
    wprintf(L"rip: %08x, rsp: %08x\r\n", rip, rsp);
    for (int i = 0; i < 16; i++, rip++)
        wprintf(L"%02x ", *(uint8_t *)rip);
    wprintf(L"\r\n");
    for (int i = 0; i < 16; i++, rsp += 8)
        wprintf(L"%016x: %016x\r\n", rsp, *(uint64_t *)rsp);
    wprintf(L"\r\n");
}

static inline void __invpcid(unsigned long pcid, unsigned long addr,
                             unsigned long type)
{
    struct
    {
        uint64_t d[2];
    } desc = {{pcid, addr}};
    /*
     * The memory clobber is because the whole point is to invalidate
     * stale TLB entries and, especially if we're flushing global
     * mappings, we don't want the compiler to reorder any subsequent
     * memory accesses before the TLB flush.
     *
     * The hex opcode is invpcid (%ecx), %eax in 32-bit mode and
     * invpcid (%rcx), %rax in long mode.
     */
    asm volatile(".byte 0x66, 0x0f, 0x38, 0x82, 0x01"
                 :
                 : "m"(desc), "a"(type), "c"(&desc)
                 : "memory");
}
int hoge;
_Noreturn void guest_entry(void);

uint32_t get_seg_limit(uint32_t selector)
{
    uint32_t limit;
    asm volatile("lsl %1, %0"
                 : "=r"(limit)
                 : "r"(selector));
    return limit;
}
int32_t get_seg_access_rights(uint32_t selector)
{
    uint32_t access_rights;
    asm volatile("lar %1, %0"
                 : "=r"(access_rights)
                 : "r"(selector));
    return access_rights >> 8;
}
uint64_t get_seg_base(uint32_t selector) { return 0; }

const uint64_t kPageSize4K = 4096;
const uint64_t kPageSize2M = 512 * kPageSize4K;
const uint64_t kPageSize1G = 512 * kPageSize2M;

uint64_t pml4_table[512] __attribute__((aligned(4096)));
;
uint64_t pdp_table[512] __attribute__((aligned(4096)));
;
uint64_t page_directory[512][512] __attribute__((aligned(4096)));
;
uint64_t pml4_table_2[512] __attribute__((aligned(4096)));
;

uint16_t exec_fuzz(void)
{
    uint16_t instr_selector = input_buf[index_count++];
    // index_count+=1;
    instr_selector = instr_selector % 70;
    invept_t inv;
    uint64_t zero = 0;
    uint64_t p;
    uint32_t index;
    uint64_t value;
    switch (instr_selector)
    {
    case 0:
        break;
    case 1:
        break;
    case 2:
        break;
    case 3:
        break;
    case 4:
        break;
    case 5:
        break;
    case 6:
        break;
    case 7:
        break;
    case 8:
        break;
    case 9:
        break;
    case 10:
        if (input_buf[index_count++] % 3 == 0)
        {
            asm volatile("cpuid" ::"a"(input_buf[index_count++] % 0x21), "c"(input_buf[index_count++] % 0x21)
                         : "ebx", "edx");
        }
        if (input_buf[index_count++] % 3 == 1)
        {
            asm volatile("cpuid" ::"a"(0x80000000 | input_buf[index_count++] % 0x9)
                         : "ebx", "edx");
        }
        else
        {
            asm volatile("cpuid" ::"a"(0x4fffffff & (input_buf[index_count++] << 16 | input_buf[index_count++]))
                         : "ebx", "edx");
        }
        break;
    case 11:
        // asm volatile ("getsec":::); // 11 vmexit x vmexit vmx non-root
        break;
    case 12:
        asm volatile("hlt"); // 12 x
        break;
    case 13:
        asm volatile("invd" ::
                         :); // 13
        break;
    case 14:
        p = get64b(index_count);
        index_count += 4;
        asm volatile("invlpg %0"
                     :
                     : "m"(p)); // 14 vmexit o
        break;
    case 15:
        p = get64b(index_count);
        index_count += 4;
        asm volatile("rdpmc"
                     : "+c"(p)
                     :
                     : "%rax"); // 15 vmexit o sometimes hang
        break;
    case 16:
        asm volatile("rdtsc"); // 16
        break;
    case 17:
        asm volatile("rsm" ::
                         :); // 17 0x80000021x sometimes hang
        break;
    case 18:
        break;
    case 19:
        value = get64b(index_count);
        index_count += 4;
        asm volatile("vmclear %0" ::"m"(value));
        break;
    case 20:
        asm volatile("vmlaunch\n\t");
        break;
    case 21:
        value = get64b(index_count);
        index_count += 4;
        vmptrld(&value);
        break;
    case 22:
        vmptrst(&value);
        break;
    case 23:
        vmread(vmcs_index[input_buf[index_count++] % vmcs_num]);
        break;
    case 24:
        // asm volatile("vmresume\n\t");
        break;
    case 25:
        value = get64b(index_count);
        index_count += 4;
        vmwrite(vmcs_index[input_buf[index_count++] % vmcs_num], value);
        break;
    case 26:
        asm volatile("vmxoff");
        break;
    case 27:
        value = get64b(index_count);
        index_count += 4;
        asm volatile("vmxon %0" ::"m"(value));
        break;
    case 28:
        switch (input_buf[index_count++] % 4)
        {
        case 0:
            value = get64b(index_count);
            index_count += 4;
            switch (input_buf[index_count++] % 4)
            {
            case 0:
                asm volatile("movq %0, %%cr0"
                             : "+c"(value)
                             :
                             : "%rax");
            case 1:
                asm volatile("movq %0, %%cr3"
                             : "+c"(value)
                             :
                             : "%rax");
            case 2:
                asm volatile("movq %0, %%cr4"
                             : "+c"(value)
                             :
                             : "%rax");
            case 3:
                asm volatile("movq %0, %%cr8"
                             : "+c"(value)
                             :
                             : "%rax");
            }
            break;
        case 1:
            switch (input_buf[index_count++] % 4)
            {
            case 0:
                asm volatile("movq %%cr0, %0"
                             : "=c"(zero)
                             :
                             : "%rbx");
            case 1:
                asm volatile("movq %%cr3, %0"
                             : "=c"(zero)
                             :
                             : "%rbx");
            case 2:
                asm volatile("movq %%cr4, %0"
                             : "=c"(zero)
                             :
                             : "%rbx");
            case 3:
                asm volatile("movq %%cr8, %0"
                             : "=c"(zero)
                             :
                             : "%rbx");
            }
            break;
        case 2:
            asm volatile("clts");
            break;
        case 3:
            value = (uint16_t)get32b(index_count);
            index_count += 2;
            asm volatile("lmsw %0"
                         :
                         : "m"(value));
            break;
        }
        break;
    case 29:
        asm volatile("movq %%dr0, %0"
                     : "=c"(zero)
                     :
                     : "%rbx");
        asm volatile("movq %%dr1, %0"
                     : "=c"(zero)
                     :
                     : "%rbx");
        asm volatile("movq %%dr2, %0"
                     : "=c"(zero)
                     :
                     : "%rbx");
        asm volatile("movq %%dr3, %0"
                     : "=c"(zero)
                     :
                     : "%rbx");
        asm volatile("movq %%dr4, %0"
                     : "=c"(zero)
                     :
                     : "%rbx");
        asm volatile("movq %%dr5, %0"
                     : "=c"(zero)
                     :
                     : "%rbx");
        asm volatile("movq %%dr6, %0"
                     : "=c"(zero)
                     :
                     : "%rbx");
        asm volatile("movq %%dr7, %0"
                     : "=c"(zero)
                     :
                     : "%rbx");
        asm volatile("movq %0, %%dr0"
                     : "+c"(get64b(index_count))
                     :
                     : "%rax");
        asm volatile("movq %0, %%dr1"
                     : "+c"(get64b(index_count))
                     :
                     : "%rax");
        asm volatile("movq %0, %%dr2"
                     : "+c"(get64b(index_count))
                     :
                     : "%rax");
        asm volatile("movq %0, %%dr3"
                     : "+c"(get64b(index_count))
                     :
                     : "%rax");
        asm volatile("movq %0, %%dr4"
                     : "+c"(get64b(index_count))
                     :
                     : "%rax");
        asm volatile("movq %0, %%dr5"
                     : "+c"(get64b(index_count))
                     :
                     : "%rax");
        asm volatile("movq %0, %%dr6"
                     : "+c"(get64b(index_count))
                     :
                     : "%rax");
        asm volatile("movq %0, %%dr7"
                     : "+c"(get64b(index_count))
                     :
                     : "%rax");
        break;
    case 30:
        asm volatile("mov %0, %%dx" ::"r"(input_buf[index_count++]));
        asm volatile("mov %0, %%eax" ::"r"(get32b(index_count)));
        index_count += 2;
        asm volatile("out %eax, %dx");
        asm volatile("mov %0, %%dx" ::"r"(input_buf[index_count++]));
        asm volatile("in %dx, %eax");
        break;
    case 31:
        index = get32b(index_count);
        index_count += 2;
        asm volatile("rdmsr" ::"c"(index & 0x1FFF));
        asm volatile("rdmsr" ::"c"(0xC0000000 | (index & 0x1FFF)));
        break;
    case 32:
        index = get32b(index_count);
        index_count += 2;
        value = get64b(index_count);
        index_count += 4;
        asm volatile("wrmsr" ::"c"(index & 0x1FFF), "a"(value & 0xFFFFFFFF), "d"(value >> 32));
        asm volatile("wrmsr" ::"c"(0xC0000000 | (index & 0x1FFF)), "a"(value & 0xFFFFFFFF), "d"(value >> 32));
        break;
    case 33:
        break;
    case 34:
        break;
    case 35:
        break;
    case 36:
        asm volatile("mwait"); // 36
        break;
    case 37:
        break;
    case 38:
        break;
    case 39:
        asm volatile("monitor"); // 39
        break;
    case 40:
        asm volatile("pause"); // 40
        break;
    case 41:
        break;
    case 42:
        break;
    case 43:
        break;
    case 44:
        break;
    case 45:
        break;
    case 46:
        break;
    case 47:
        break;
    case 48:
        break;
    case 49:
        break;
    case 50:
        inv.rsvd = 0;
        inv.ptr = get64b(index_count);
        index_count += 4;
        invept((uint64_t)0, &inv);
        break;
    case 51:
        asm volatile("rdtscp"); // 51 vmexit sometimes hang
        break;
    case 52:
        break;
    case 53:
        inv.rsvd = 0;
        inv.ptr = get64b(index_count);
        index_count += 4;
        invvpid((uint64_t)0, &inv);
        break;
    case 54:
        asm volatile("wbnoinvd" ::
                         :); // 54
        asm volatile("wbinvd" ::
                         :); // 54
        break;
    case 55:
        asm volatile("xsetbv" ::
                         :); // 55 sometimes hang
        break;
    case 56:
        break;
    case 57:
        asm volatile("rdrand %0"
                     : "+c"(zero)
                     :
                     : "%rax"); // 57
        break;
    case 58:
        __invpcid(0, 0, 0); // 58 vmexit sometimes hang
        break;
    case 59:
        asm volatile("vmfunc" ::
                         :);
        asm volatile("mov 0, %eax");
        asm volatile("vmfunc" ::
                         :);
        break;
    case 60:
        asm volatile("encls" ::
                         :); // 60 vmexit sometimes hang
        break;
    case 61:
        asm volatile("rdseed %0"
                     : "+c"(zero)
                     :
                     : "%rax"); // 61
        break;
    case 65:
        asm volatile("pconfig"); // 65 vmexit sometimes hang
        break;
    default:
        break;
    }
    return instr_selector;
}
uint16_t exec_fuzz_L2(void)
{
    uint16_t instr_selector = input_buf[index_count++];
    // index_count+=1;
    instr_selector = instr_selector % 70;
    invept_t inv;
    uint64_t zero = 0;
    uint64_t p;
    uint32_t index;
    uint64_t value;
    switch (instr_selector)
    {
    case 0:
        break;
    case 1:
        break;
    case 2:
        break;
    case 3:
        break;
    case 4:
        break;
    case 5:
        break;
    case 6:
        break;
    case 7:
        break;
    case 8:
        break;
    case 9:
        break;
    case 10:
        if (input_buf[index_count++] % 3 == 0)
        {
            asm volatile("cpuid" ::"a"(input_buf[index_count++] % 0x21), "c"(input_buf[index_count++] % 0x21)
                         : "ebx", "edx");
        }
        if (input_buf[index_count++] % 3 == 1)
        {
            asm volatile("cpuid" ::"a"(0x80000000 | input_buf[index_count++] % 0x9)
                         : "ebx", "edx");
        }
        else
        {
            asm volatile("cpuid" ::"a"(0x4fffffff & (input_buf[index_count++] << 16 | input_buf[index_count++]))
                         : "ebx", "edx");
        }
        break;
    case 11:
        // asm volatile ("getsec":::); // 11 vmexit x vmexit vmx non-root
        break;
    case 12:
        asm volatile("hlt"); // 12 x
        break;
    case 13:
        asm volatile("invd" ::
                         :); // 13
        break;
    case 14:
        p = get64b(index_count);
        index_count += 4;
        asm volatile("invlpg %0"
                     :
                     : "m"(p)); // 14 vmexit o
        break;
    case 15:
        p = get64b(index_count);
        index_count += 4;
        asm volatile("rdpmc"
                     : "+c"(p)
                     :
                     : "%rax"); // 15 vmexit o sometimes hang
        break;
    case 16:
        asm volatile("rdtsc"); // 16
        break;
    case 17:
        asm volatile("rsm" ::
                         :); // 17 0x80000021x sometimes hang
        break;
    case 18:
        break;
    case 19:
        value = get64b(index_count);
        index_count += 4;
        asm volatile("vmclear %0" ::"m"(value));
        break;
    case 20:
        asm volatile("vmlaunch\n\t");
        break;
    case 21:
        value = get64b(index_count);
        index_count += 4;
        vmptrld(&value);
        break;
    case 22:
        // vmptrst(&value);
        asm volatile("vmptrst %0"
                     :
                     : "m"(zero)
                     : "cc");
        break;
    case 23:
        // vmread(vmcs_index[input_buf[index_count++]%vmcs_num]);
        asm volatile("vmread %%rax, %%rdx"
                     : "=d"(zero)
                     : "a"(vmcs_index[input_buf[index_count++] % vmcs_num])
                     : "cc");
        break;
    case 24:
        // asm volatile("vmresume\n\t");
        break;
    case 25:
        value = get64b(index_count);
        index_count += 4;
        // vmwrite(vmcs_index[input_buf[index_count++]%vmcs_num],value);
        asm volatile("vmwrite %%rdx, %%rax"
                     :
                     : "a"(vmcs_index[input_buf[index_count++] % vmcs_num]), "d"(value)
                     : "cc", "memory");
        break;
    case 26:
        asm volatile("vmxoff");
        break;
    case 27:
        value = get64b(index_count);
        index_count += 4;
        asm volatile("vmxon %0" ::"m"(value));
        break;
    case 28:
        switch (input_buf[index_count++] % 4)
        {
        case 0:
            value = get64b(index_count);
            index_count += 4;
            switch (input_buf[index_count++] % 4)
            {
            case 0:
                asm volatile("movq %0, %%cr0"
                             : "+c"(value)
                             :
                             : "%rax");
            case 1:
                asm volatile("movq %0, %%cr3"
                             : "+c"(value)
                             :
                             : "%rax");
            case 2:
                asm volatile("movq %0, %%cr4"
                             : "+c"(value)
                             :
                             : "%rax");
            case 3:
                asm volatile("movq %0, %%cr8"
                             : "+c"(value)
                             :
                             : "%rax");
            }
            break;
        case 1:
            switch (input_buf[index_count++] % 4)
            {
            case 0:
                asm volatile("movq %%cr0, %0"
                             : "=c"(zero)
                             :
                             : "%rbx");
            case 1:
                asm volatile("movq %%cr3, %0"
                             : "=c"(zero)
                             :
                             : "%rbx");
            case 2:
                asm volatile("movq %%cr4, %0"
                             : "=c"(zero)
                             :
                             : "%rbx");
            case 3:
                asm volatile("movq %%cr8, %0"
                             : "=c"(zero)
                             :
                             : "%rbx");
            }
            break;
        case 2:
            asm volatile("clts");
            break;
        case 3:
            value = (uint16_t)get32b(index_count);
            index_count += 2;
            asm volatile("lmsw %0"
                         :
                         : "m"(value));
            break;
        }
        break;
    case 29:
        asm volatile("movq %%dr0, %0"
                     : "=c"(zero)
                     :
                     : "%rbx");
        asm volatile("movq %%dr1, %0"
                     : "=c"(zero)
                     :
                     : "%rbx");
        asm volatile("movq %%dr2, %0"
                     : "=c"(zero)
                     :
                     : "%rbx");
        asm volatile("movq %%dr3, %0"
                     : "=c"(zero)
                     :
                     : "%rbx");
        asm volatile("movq %%dr4, %0"
                     : "=c"(zero)
                     :
                     : "%rbx");
        asm volatile("movq %%dr5, %0"
                     : "=c"(zero)
                     :
                     : "%rbx");
        asm volatile("movq %%dr6, %0"
                     : "=c"(zero)
                     :
                     : "%rbx");
        asm volatile("movq %%dr7, %0"
                     : "=c"(zero)
                     :
                     : "%rbx");
        asm volatile("movq %0, %%dr0"
                     : "+c"(get64b(index_count))
                     :
                     : "%rax");
        asm volatile("movq %0, %%dr1"
                     : "+c"(get64b(index_count))
                     :
                     : "%rax");
        asm volatile("movq %0, %%dr2"
                     : "+c"(get64b(index_count))
                     :
                     : "%rax");
        asm volatile("movq %0, %%dr3"
                     : "+c"(get64b(index_count))
                     :
                     : "%rax");
        asm volatile("movq %0, %%dr4"
                     : "+c"(get64b(index_count))
                     :
                     : "%rax");
        asm volatile("movq %0, %%dr5"
                     : "+c"(get64b(index_count))
                     :
                     : "%rax");
        asm volatile("movq %0, %%dr6"
                     : "+c"(get64b(index_count))
                     :
                     : "%rax");
        asm volatile("movq %0, %%dr7"
                     : "+c"(get64b(index_count))
                     :
                     : "%rax");
        break;
    case 30:
        asm volatile("mov %0, %%dx" ::"r"(input_buf[index_count++]));
        asm volatile("mov %0, %%eax" ::"r"(get32b(index_count)));
        index_count += 2;
        asm volatile("out %eax, %dx");
        asm volatile("mov %0, %%dx" ::"r"(input_buf[index_count++]));
        asm volatile("in %dx, %eax");
        break;
    case 31:
        index = get32b(index_count);
        index_count += 2;
        asm volatile("rdmsr" ::"c"(index & 0x1FFF));
        asm volatile("rdmsr" ::"c"(0xC0000000 | (index & 0x1FFF)));
        break;
    case 32:
        index = get32b(index_count);
        index_count += 2;
        value = get64b(index_count);
        index_count += 4;
        asm volatile("wrmsr" ::"c"(index & 0x1FFF), "a"(value & 0xFFFFFFFF), "d"(value >> 32));
        asm volatile("wrmsr" ::"c"(0xC0000000 | (index & 0x1FFF)), "a"(value & 0xFFFFFFFF), "d"(value >> 32));
        break;
    case 33:
        break;
    case 34:
        break;
    case 35:
        break;
    case 36:
        asm volatile("mwait"); // 36
        break;
    case 37:
        break;
    case 38:
        break;
    case 39:
        asm volatile("monitor"); // 39
        break;
    case 40:
        asm volatile("pause"); // 40
        break;
    case 41:
        break;
    case 42:
        break;
    case 43:
        break;
    case 44:
        break;
    case 45:
        break;
    case 46:
        break;
    case 47:
        break;
    case 48:
        break;
    case 49:
        break;
    case 50:
        inv.rsvd = 0;
        inv.ptr = get64b(index_count);
        index_count += 4;
        invept((uint64_t)0, &inv);
        break;
    case 51:
        asm volatile("rdtscp"); // 51 vmexit sometimes hang
        break;
    case 52:
        break;
    case 53:
        inv.rsvd = 0;
        inv.ptr = get64b(index_count);
        index_count += 4;
        invvpid((uint64_t)0, &inv);
        break;
    case 54:
        asm volatile("wbnoinvd" ::
                         :); // 54
        asm volatile("wbinvd" ::
                         :); // 54
        break;
    case 55:
        asm volatile("xsetbv" ::
                         :); // 55 sometimes hang
        break;
    case 56:
        break;
    case 57:
        asm volatile("rdrand %0"
                     : "+c"(zero)
                     :
                     : "%rax"); // 57
        break;
    case 58:
        __invpcid(0, 0, 0); // 58 vmexit sometimes hang
        break;
    case 59:
        // asm volatile ("vmfunc":::);
        asm volatile("mov 0, %eax");
        asm volatile("vmfunc" ::
                         :);
        break;
    case 60:
        asm volatile("encls" ::
                         :); // 60 vmexit sometimes hang
        break;
    case 61:
        asm volatile("rdseed %0"
                     : "+c"(zero)
                     :
                     : "%rax"); // 61
        break;
    case 65:
        asm volatile("pconfig"); // 65 vmexit sometimes hang
        break;
    default:
        break;
    }
    return instr_selector;
}

void host_entry(uint64_t arg)
{
    // uint64_t *ptr = (uint64_t *)vmxon_region;
    // vmxoff(/)
    //     asm volatile ("mov 0, %eax");
    //     asm volatile ("mov 1, %ecx");
    // asm volatile ("vmfunc":::);
    // asm volatile ("vmxoff");
    // asm volatile ("vmxon %0" :: "m" (ptr));

    // vmptrld(ptr);
    // vmptrld(&vmxonptr);
    // vmptrld(&vmxonptr);
    input_buf[4003] = 0;
    // __builtin_longjmp(env, 1);
    uint64_t reason = vmread(0x4402);
    uint64_t rip = vmread(0x681E); // Guest RIP
    uint64_t len = vmread(0x440C); // VM-exit instruction length
    // if(reason == 18){
    //     if(arg>1){
    //         wprintf(L" exec %d\n",arg);
    //         vmwrite(0x681e, rip+len);
    //         asm volatile("vmresume\n\t");
    //     }
    // }
    // if(current_evmcs){
    //     evmcs_vmread(0x4402, &reason);
    //     evmcs_vmread(0x681E, &rip);
    //     evmcs_vmread(0x440C, &len);
    // }
    wprintf(L"exit reason = %d, rip = 0x%x, len = %d\n", reason, rip, len);
    // wprintf(L"vmwrite(0x2004, 0x%x);\n", vmread(0x2004));
    if (reason == 18)
    {
        vmwrite(0x681e, rip + len);
        // wprintf(L"!0x681e: %x\n",vmread(0x681e));

        // goto fuzz;
    }
    if (guest_hang == 1)
    {
        if (reason & 0x80000000)
        {
            wprintf(L"guest_hang==1\n");
            __builtin_longjmp(env, 1);
        }
        else
        {
            guest_hang = 0;
            reason = 18;
            arg = 1;
            vmwrite(0x681E, (uint64_t)guest_entry);
            vmwrite(0x440c, 0);
            goto fuzz;
        }
    }
    if (reason & 0x80000000)
    {
        // wprintf(L"VM exit reason 0x%x\n",reason);
        wprintf(L"Error Number is %d\r\n", vmread(0x4400));

        if (shiftcount < 61)
        {
            uint64_t wvalue = 0;
            if (prev_ind < 0x2000)
            {
                if (shiftcount > 12)
                {
                    __builtin_longjmp(env, 1);
                }
                wvalue = (uint16_t)((uint16_t)prev_val ^ (0xf << (shiftcount)));
            }
            else if (prev_ind < 0x4000)
            {
                wvalue = (uint64_t)((uint64_t)prev_val ^ (0xf << (shiftcount)));
            }
            else if (prev_ind < 0x6000)
            {
                if (shiftcount > 28)
                {
                    __builtin_longjmp(env, 1);
                }
                wvalue = (uint32_t)((uint32_t)prev_val ^ (0xf << (shiftcount)));
            }
            else
            {
                wvalue = (uint64_t)((uint64_t)prev_val ^ (0xf << (shiftcount)));
            }
            if ((prev_ind & 0x0f00) != 0xc00)
            {
                if (prev_ind == 0x400e || prev_ind == 0x681c || prev_ind == 0x681e || prev_ind == 0x6816 || prev_ind == 0x681E || prev_ind == 0x2800 || prev_ind == 0x2000 || prev_ind == 0x2002 || prev_ind == 0x2004 || prev_ind == 0x2006 || prev_ind == 0x2008 || prev_ind == 0x200a || prev_ind == 0x200c || prev_ind == 0x200e || prev_ind == 0x2012 || prev_ind == 0x2014 || prev_ind == 0x2016 || prev_ind == 0x2024 || prev_ind == 0x2026 || prev_ind == 0x2028 || prev_ind == 0x202a)
                {
                    ;
                }
                else
                {
                    vmwrite(prev_ind, wvalue);
                    // wprintf(L"vmwrite(0x%x,0x%x);\n",windex,vmread(windex));
                    wprintf(L"vmwrite(0x%x,0x%x);\n", prev_ind, wvalue);
                }
            }

            vmwrite(0x681E, (uint64_t)guest_entry);
            vmwrite(0x440c, 0);

            if (current_evmcs)
                for (int i = 0; i < vmcs_num; i++)
                {
                    if (current_evmcs)
                        evmcs_vmwrite(vmcs_index[i], vmread(vmcs_index[i]));
                    // wprintf(L"vmwrite(0x%x, 0x%x);\n", vmcs_index[i], vmread(vmcs_index[i]));
                }
            if (current_evmcs)
            {
                /* HOST_RIP */
                current_evmcs->hv_clean_fields &= ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_HOST_GRP1;
                /* HOST_RSP */
                current_evmcs->hv_clean_fields &= ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_HOST_POINTER;
            }
            shiftcount++;
            asm volatile("vmresume\n\t");
            wprintf(L"VMRESUME failed: \r\n");
        }
        print_exitreason(reason);

        // wprintf(L"Initialize VMCS\r\n");

        for (int i = 0; i < vmcs_num; i++)
        {
            if (!(0
                  // (vmcs_index[i] & 0x0f00) == 0xc00
                  // || (vmcs_index[i] & 0x0f00) == 0x400
                  // (vmcs_index[i] & 0x0f00) == 0x400
                  ))
            {
                // wprintf(L"vmwrite(0x%x,0x%x);\n", vmcs_index[i], vmread(vmcs_index[i]));
                vmwrite(vmcs_index[i], restore_vmcs[i]);
            }
        }
        guest_hang = 1;
        asm volatile("vmresume\n\t");
        __builtin_longjmp(env, 1);
        vmwrite(0x681E, (uint64_t)guest_entry);
        asm volatile("vmresume\n\t");
    }
    // if (reason == 0x1|| reason == 62|| reason == 43|| reason ==48||reason == 47 ){
    if (reason == 0x0 || reason == 0x1 || reason == 43 || reason == 48 || reason == 47)
    {
        // // initialize VMCS
        // wprintf(L"Initialize VMCS\r\n");
        // for(int i=0; i < vmcs_num; i++){
        //     if(!(
        //         // (vmcs_index[i] & 0x0f00) == 0xc00
        //         // || (vmcs_index[i] & 0x0f00) == 0x400
        //         (vmcs_index[i] & 0x0f00) == 0x400
        //     )){
        //         // wprintf(L"vmwrite(0x%x,0x%x);\n", vmcs_index[i], vmread(vmcs_index[i]));
        //         vmwrite(vmcs_index[i],restore_vmcs[i]);
        //     }
        // }
        reason = 18;
        arg = 1;
        vmwrite(0x681E, (uint64_t)guest_entry);
        vmwrite(0x440c, 0);
        goto fuzz;
    }
    if (reason == 54 || reason == 39 || reason == 40 || reason == 36 || reason == 46 || reason == 50 || reason == 16 || reason == 11 || reason == 57 || reason == 16 || reason == 61 || reason == 15 || reason == 13 || reason == 58 || reason == 19 || reason == 12 || reason == 14 || reason == 53 || reason == 51 || reason == 24 || reason == 23 || reason == 21 || reason == 27 || reason == 62 || reason == 28 || reason == 20 || reason == 22 || reason == 25 || reason == 26 || reason == 55 || reason == 31 || reason == 32 || reason == 30 || reason == 59 || reason == 10)
    {
        vmwrite(0x681E, rip + len);
        asm volatile("vmresume\n\t");
        goto fuzz;
        // __builtin_longjmp(env, 1);
    }
    if (reason == 2 || reason == 7 || reason == 8 || reason == 29 || reason == 37 || reason == 52)
    {
        reason = 18;
        arg = 1;
        vmwrite(0x681E, (uint64_t)guest_entry);
        vmwrite(0x440c, 0);
        goto fuzz;
    }
    if (reason != 18)
    {
        wprintf(L"VM exit reason %d\n", reason);
        if (reason == 65)
        {
            __builtin_longjmp(env, 1);
        }
        vmwrite(0x681E, rip + len);
        asm volatile("vmresume\n\t");
        // __builtin_longjmp(env, 1);
    }

    if (reason == 18)
    {
    fuzz:
        // if (arg == 0) {
        //     // vmcall_with_vmcall_number(13);
        //     // print_exitreason(reason);
        //     wprintf(L"goodbye:)\n");
        //     __builtin_longjmp(env, 1);
        // }
        loop_count++;
        wprintf(L"%d\r\n", loop_count);
        if (loop_count > 1000)
            __builtin_longjmp(env, 1);

        uint16_t is_input_ready = 0;
        uint16_t windex;
        uint64_t wvalue;
        // if (1) {
        // while(1){
        input_buf[4001] = 1;

        vmwrite(0x2, loop_count);
        is_input_ready = input_buf[4000];
        while (!is_input_ready)
        {
            is_input_ready = input_buf[4000];
        }
        input_buf[4000] = 0;
        input_buf[4003] = 1;
        // wprintf(L"0x681E: %x\n", vmread(0x681e));
        // wprintf(L"guest_entry: %x\n", (uint64_t)guest_entry);

        wvalue = (uint64_t)input_buf[3] << 48 | (uint64_t)input_buf[3] << 32 | (uint64_t)input_buf[2] << 16 | (uint64_t)input_buf[1];
        invept_t inv;
        uint64_t eptp = (uint64_t)pml4_table;
        uint64_t type = input_buf[1] % 4;
        inv.rsvd = 0;
        inv.ptr = wvalue;
        if (input_buf[1] % 2 == 0)
        {
            inv.ptr = eptp;
        }
        // i.ptr = wvalue;
        if (input_buf[3] % 2)
            // invept((uint64_t)type,&inv);
            inv.rsvd = wvalue;
        inv.rsvd = eptp;
        inv.ptr = input_buf[1] % 4;
        if (input_buf[4] % 2)
            // invvpid(type,&inv);
            wprintf(L"guest_entry: %x\n", (uint64_t)guest_entry);
        // int tmp = vmcs_num;
        int tmp = 70;
        // __invpcid(3, 0, 3); // 58 vmexit sometimes hang

        // vmwrite(0x4002, 0x262cf243&~(1<<6|1<<9));
        // vmwrite(0x4002, 0x262cf243|0xf<<28);
        // vmwrite(0x4002, 0x262cf243|1<<31);
        // wprintf(L"   !!! 0x%x\n", vmcs_index[tmp]);
        // for (int i = 0; i < 4092/sizeof(uint16_t); i += 4) {
        for (int i = 0 * 4; i < vmcs_num * 4; i += 4)
        {
            // for (int i =tmp*4; i <vmcs_num*4; i += 4) {
            // for (int i = tmp*4; i <100*4; i += 4) {
            // if(i/4 >= 60 && i/4 <= 105){continue;}
            // for (int i = 4*72; i <4*73; i += 4) {
            // for (int i = 4*60; i <4*71; i += 4) {
            // for (int i = 50*4; i <70*4; i += 4) {
            if (i / 4 == vmcs_num)
            {
                break;
            }
            windex = i / 4;
            windex = vmcs_index[windex];
            vmread(windex);
            wvalue = ((uint64_t *)(input_buf) + i / 4)[0];
            // wrmsr(0x40000105,windex);
            // wrmsr(0x40000105,wvalue);
            // wprintf(L"input_buf[%x:%d] = 0x%x\n",i*2,i, wvalue);
            // wvalue = (uint64_t)input_buf[i];
            if (
                /* VMCS 16-bit guest-state fields 0x80x */
                // (windex & 0xfff0) == 0x800 ||
                // (windex >= 0x810 && windex < 0xC00)
                // (windex >= 0x812 && windex < 0xC00)
                // (windex >= 0x810 && windex < 0xC00)
                // (windex > 0x810 && windex < 0xC00) ||

                /* VMCS 64-bit control fields 0x20xx */
                // (windex & 0xff00) == 0x2000
                0 || windex == 0x2000 || windex == 0x2002 || windex == 0x2004 || windex == 0x2006 || windex == 0x2008 || windex == 0x200a || windex == 0x200c || windex == 0x200e || windex == 0x2012 || windex == 0x2014 || windex == 0x2016 || windex == 0x2024 || windex == 0x201a || windex == 0x2026 || windex == 0x2028 || windex == 0x202a
                // || (windex & 0xff00) == 0x2000
                /* VMCS 64-bit guest state fields 0x28xx */
                // (windex & 0xff00) == 0x2800 ||
                // || (windex >= 0x2800 && windex < 0x2806)
                || windex == 0x2800 || windex == 0x2802 // 0x800000021
                // || windex == 0x2804 // PAT
                // || windex == 0x2806 // EFER
                || windex == 0x2808 // IA32_PERF_GLOBAL_CTRL
                || (windex >= 0x280a && windex < 0x2C00)
                /* VMCS natural width guest state fields 0x68xx */
                // || (windex & 0xff00) == 0x6800
                || windex == 0x6802

                || windex == 0x6806 // VMCS_GUEST_ES_BASE
                || windex == 0x6808 // VMCS_GUEST_CS_BASE
                || windex == 0x680a // VMCS_GUEST_SS_BASE
                || windex == 0x680c // VMCS_GUEST_DS_BASE
                || windex == 0x680e // VMCS_GUEST_FS_BASE
                || windex == 0x6810 // VMCS_GUEST_GS_BASE
                || windex == 0x6812 // VMCS_GUEST_LDTR_BASE
                || windex == 0x6814 // VMCS_GUEST_TR_BASE
                || windex == 0x6816 // VMCS_GUEST_GDTR_BASE
                || windex == 0x6818 // VMCS_GUEST_IDTR_BASE
                // || windex == 0x681a  // VMCS_GUEST_DR7
                || windex == 0x681c // VMCS_GUEST_RSP
                || windex == 0x681e // VMCS_GUEST_RIP
                || windex == 0x6820 // VMCS_GUEST_RFLAGS
                || windex == 0x6822 // VMCS_GUEST_PENDING_DBG_EXCEPTIONS 0x800000021
                || windex == 0x6824 // VMCS_GUEST_IA32_SYSENTER_ESP_MSR
                || windex == 0x6826 // VMCS_GUEST_IA32_SYSENTER_EIP_MSR
                || windex == 0x6828 // VMCS_GUEST_IA32_S_CET
                || windex == 0x682a // VMCS_GUEST_SSP
                || windex == 0x682c // VMCS_GUEST_INTERRUPT_SSP_TABLE_ADDR

                /* VMCS host state fields */
                || (windex & 0xfff0) == 0xc00  /* VMCS 16-bit host-state fields 0xc0x */
                || (windex & 0xff00) == 0x2c00 /* VMCS 64-bit host state fields 0x2cxx */
                || (windex & 0xff00) == 0x4c00 /* VMCS 64-bit host state fields 0x2cxx */
                || (windex & 0xff00) == 0x6c00 /* VMCS natural width host state fields 0x6cxx*/
                // || windex == 0x4000//PIN_BASED_EXEC_CONTROLS
                // || windex == 0x4002//PROCESSOR_BASED_VMEXEC_CONTROLS
                // || windex == 0x400a
                // || windex == 0x401e//SECONDARY_VMEXEC_CONTROL
                // || windex == 0x400c//VMEXIT_CONTROLS
                // || windex == 0x4012//VMENTRY_CONTROLS
                // || windex == 0x400e
                // || windex == 0x4010 // vmexit msr load count
                // || windex == 0x4014 // vmentry msr load count
                // || windex == 0x4016 //VMENTRY_INTERRUPTION_INFO sometimes hang
                // || windex == 0x4826 // guest activity state
                // || windex == 0x4824 // guest interuptibility state

                // LIMIT
                // || windex == 0x4800
                // || windex == 0x4802
                // || windex == 0x4804
                // || windex == 0x4806
                // || windex == 0x4808
                // || windex == 0x480a
                || windex == 0x480c // ldtr limit
                || windex == 0x480e // tr limit
                // || windex == 0x4810
                // || windex == 0x4812

                // || windex == 0x4814 // ES_ACCESS_RIGHTS
                || windex == 0x4816 // CS_ACCESS_RIGHTS
                || windex == 0x4818 // SS_ACCESS_RIGHTS
                // || windex == 0x481a // DS_ACCESS_RIGHTS
                // || windex == 0x481c // FS_ACCESS_RIGHTS
                // || windex == 0x481e // GS_ACCESS_RIGHTS
                // || windex == 0x4820
                // || windex == 0x4822
                // || windex == 0x4824
                // || windex == 0x4826
                // || windex == 0x4828
                // || windex == 0x4000
                // || windex == 0x4002
                // || windex == 0x4004
                // || windex == 0x6000
                // || windex == 0x6004
                // || windex == 0x6002

                // RO fields
                //  ||(windex & 0xff00) == 0x2400
                //  ||(windex & 0xff00) == 0x4400
                //  ||(windex & 0xff00) == 0x6400
                //  || windex ==0x400a
            )
            {
                continue;
            }
            // */
            if (windex < 0x2000)
            { // 16b
                wvalue = (uint16_t)wvalue;
            }
            else if (windex < 0x4000)
            { // 64b
                wvalue = (uint64_t)wvalue;
            }
            else if (windex < 0x6000)
            { // 32b
                wvalue = (uint32_t)wvalue;
            }
            else
            { // 64b
                wvalue = (uint64_t)wvalue;
            }
            if (windex == 0x812)
            {
                wvalue = wvalue % (512);
            }
            if (windex == 0x2018)
            {
                wvalue = wvalue % 2;
            }
            if (windex == 0x4002)
            {
                // continue;
                // wvalue &= ~(1<<22);
                // wvalue |= (1<<27);
                // wvalue |= (1<<2);
                // wvalue |= (1<<3);
                // wvalue |= (1<<7);
                // wvalue |= (1<<10);
                // wvalue |= (1<<15);
                // wvalue |= (1<<16);
                // wvalue |= (1<<19);
                // wvalue |= (1<<20);
                // wvalue |= (1<<21);
                // wvalue |= (1<<28);
                // wvalue |= (1<<30);
                wvalue |= (1 << 31);
                wvalue &= ~(1 << 27); // sometimes hang
                wvalue &= ~(1 << 22); // sometimes hang
                // wvalue &= ~(1<<15); // sometimes hang
                // wvalue &= ~(1<<16); // sometimes hang
                // wvalue &= ~(1<<19); // sometimes hang
                // wvalue &= ~(1<<20); // sometimes hang
                if (current_evmcs)
                {
                    // wvalue |= 1<<31;
                }
            }
            if (windex == 0x4000)
            {
                // continue;
                // wvalue &= ~(1);
                // wvalue &= ~(1<<3);
            }
            if (windex == 0x401e)
            {
                // wvalue &= ~(1<<1);
                // wvalue |= (1<<7);
                // wvalue &= ~(1<<7);
                // wvalue &= ~(1<<15);
                // wvalue &= ~(1<<17);
                // wvalue &= ~(1<<18);
                // wvalue &= ~(1<<19);
                // wprintf(L"wvalue 0x%x\n", wvalue);
            }
            if (windex == 0x4012)
            {
                // wvalue &= 0xf3ff;
                wvalue |= 1 << 9; // sometimes 0x800000021
            }
            if (windex == 0x4016)
            {
                // if(((wvalue >> 8)&0x7) == 6 || ((wvalue >> 8)&0x7) == 7) // not efficeint fuzz
                //     wvalue&= ~(7<<8);
                // wvalue |= 1<<9; // sometimes 0x800000021
            }
            if (windex == 0x400e || windex == 0x4010 || windex == 0x4014)
            {
                wvalue &= 0x1ff;
            }
            if (windex == 0x4816)
            { // CS access rights 9,11,13,15
                // wvalue |= 0b1001;

                // wvalue |= (1<<4);
                // wvalue |= 1<<7;
                // wvalue &= ~(1<<14);
                // wvalue |= 1<<13;
            }
            if (windex == 0x4814 || windex == 0x481a || windex == 0x481c || windex == 0x481e)
            {
                // wvalue |= (1<<4 | 1<<15|1<<0);
                // wvalue |= (1<<4);
                // wvalue |= (1<<4 | 1<<15);
                // wvalue |= (1<<1);
                // wvalue &= ~(1<<16);
                // wvalue &= ~(1<<16);
            }
            if (windex == 0x4818)
            { // SS access rights
                // wvalue |= (1<<4);
            }
            if (windex == 0x4820)
            { // SS access rights
                // wvalue &= ~(1<<4);
            }
            if (windex == 0x4822)
            { // SS access rights
                wvalue &= ~0xf;
                wvalue |= 0xb;
                // wvalue &= ~(1<<4);
                // wvalue &= ~(1<<16);
            }
            if (windex == 0x4826)
            {
                // wvalue = wvalue%(BX_ACTIVITY_STATE_MWAIT_IF+1);
                // wvalue = (wvalue == 1 || wvalue == 3 ? 0 : wvalue);
            }
            if (windex == 0x4824)
            {
                // wvalue &= ~(1<<4);
                // wvalue |= 1<<31 ;
                // wvalue &= ~((0x7) <<8);
                // wvalue |= ((0x2) <<8);
            }

            vmwrite(windex, wvalue);
            // wprintf(L"%d vmwrite(0x%x, 0x%x);\n",i/4, windex, wvalue);
            // vmwrite(0x482e,0xffffffff);
        }
        // wprintf(L"vmwrite(0x4016, 0x%x);\n", vmread(0x4016));
        // wprintf(L"vmwrite(0x2004, 0x%x);\n", vmread(0x2004));
        // wprintf(L"11:0x%x, 10-8:0x%x, 7-0:0x%x\n", (vmread(0x4016)>>11)&1, (vmread(0x4016)>>8)&0x7, vmread(0x4016)&0xff);

        // wprintf(L"0x4800 vmread:0x%x, 0x%x\n",vmread(0x4800), get_seg_limit(vmread(0x800)));
        // wprintf(L"0x4802 vmread:0x%x, 0x%x\n",vmread(0x4802), get_seg_limit(vmread(0x802)));
        // wprintf(L"0x4804 vmread:0x%x, 0x%x\n",vmread(0x4804), get_seg_limit(vmread(0x804)));
        // wprintf(L"0x4806 vmread:0x%x, 0x%x\n",vmread(0x4806), get_seg_limit(vmread(0x806)));
        // wprintf(L"0x4808 vmread:0x%x, 0x%x\n",vmread(0x4808), get_seg_limit(vmread(0x808)));
        // wprintf(L"0x480a vmread:0x%x, 0x%x\n",vmread(0x480a), get_seg_limit(vmread(0x80a)));
        vmwrite(0x4800, get_seg_limit(vmread(0x800)));
        vmwrite(0x4802, get_seg_limit(vmread(0x802)));
        vmwrite(0x4804, get_seg_limit(vmread(0x804)));
        vmwrite(0x4806, get_seg_limit(vmread(0x806)));
        vmwrite(0x4808, get_seg_limit(vmread(0x808)));
        vmwrite(0x480a, get_seg_limit(vmread(0x80a)));
        // vmwrite(vmread(VMCS_64BIT_GUEST_LINK_POINTER))
        // VMXWriteRevisionID(vmread(VMCS_64BIT_GUEST_LINK_POINTER), revision_id);
        //     vmwrite(0x681E, (uint64_t)guest_entry);
        // index_count = 0x510/2;
        // asm volatile("vmresume\n\t");
        // for(int i = 0; i < 512; i++){
        // msr_store[i*2] = 0x8<<7;
        // msr_store[i*2+1] = 0x10;
        // msr_load[i*2] = 0x8<<7;
        // msr_load[i*2+1] = 0xffffffff;
        // vmentry_msr_load[i*2] = 0x8<<7;
        // vmentry_msr_load[i*2+1] = 0x0;
        // uint64_t aa = rdmsr(0xc0000080);
        // msr_store[i*2] = 0xc0000080;
        // uint64_t bb = rdmsr(0x48c);
        // msr_load[i*2] = 0xc0000080;
        // vmentry_msr_load[i*2] = 0x48c;
        // msr_store[i*2+1] = 0x10;
        // msr_load[i*2+1] =aa;
        // vmentry_msr_load[i*2+1] = bb|1<<20;
        // msr_store[i*2] =0x10;
        // msr_store[i*2+1] =0x10;
        // msr_load[i*2] = 0x10;
        // msr_load[i*2+1] = 0x10;
        // vmentry_msr_load[i*2] = 0x10;
        // vmentry_msr_load[i*2+1] = 0x10;
        // msr_store[i*2] =0xffffffffffffffff;
        // msr_store[i*2+1] =0xffffffffffffffff;
        // msr_load[i*2] = 0xffffffffffffffff;
        // msr_load[i*2+1] = 0xffffffffffffffff;
        // vmentry_msr_load[i*2] = 0xffffffffffffffff;
        // vmentry_msr_load[i*2+1] = 0xffffffffffffffff;
        // }
        // vmwrite(0x4002,vmread(0x4002)&~(1<<31));
        // vmwrite(0x401e,vmread(0x401e)|0xffffffff);
        // wprintf(L"vmwrite(0x401e, 0x%x);\n", vmread(0x401e));
        // wprintf(L"vmwrite(0x4822, 0x%x);\n", vmread(0x4822));
        // vmwrite(0x6804,0x12804);

        enum VMX_error_code vmentry_check_failed = VMenterLoadCheckVmControls();
        if (!vmentry_check_failed)
        {
            wprintf(L"VMX CONTROLS OK!\r\n");
        }
        else
        {
            wprintf(L"VMX CONTROLS ERROR %0d\r\n", vmentry_check_failed);
        }
        vmentry_check_failed = VMenterLoadCheckHostState();
        if (!vmentry_check_failed)
        {
            wprintf(L"HOST STATE OK!\r\n");
        }
        else
        {
            wprintf(L"HOST STATE ERROR %0d\r\n", vmentry_check_failed);
        }
        uint64_t qualification;
        uint32_t is_error = VMenterLoadCheckGuestState(&qualification);
        if (!is_error)
        {
            wprintf(L"GUEST STATE OK!\r\n");
        }
        else
        {
            wprintf(L"GUEST STATE ERROR %0d\r\n", qualification);
            wprintf(L"GUEST STATE ERROR %0d\r\n", is_error);
        }
        //     wprintf(L"vmwrite(0x4016, 0x%x);\n", vmread(0x4016));
        // wprintf(L"msr 0x488, 0x%x\n", rdmsr(0x488));
        // wprintf(L"msr 0x489, 0x%x\n", rdmsr(0x489));
        // vmwrite(0x6804, vmread(0x6804)&~(1<<5));
        // wprintf(L"vmwrite(0x6804, 0x%x);\n", vmread(0x6804));
        // wprintf(L"vmwrite(0x2806, 0x%x);\n", vmread(0x2806));
        // wprintf(L"is long mode 0x2806 [efer: bit10] = %d\n", (vmread(0x2806)>>10)&1);
        // wprintf(L"pae 0x6804 [cr4: bit5] = %d\n", (vmread(0x6804)>>5)&1);
        //     wprintf(L"vmwrite(VMCS_32BIT_CONTROL_VMENTRY_EXCEPTION_ERR_CODE, 0x%x);\n", vmread(VMCS_32BIT_CONTROL_VMENTRY_EXCEPTION_ERR_CODE));
        // vmwrite(VMCS_32BIT_CONTROL_VMENTRY_INSTRUCTION_LENGTH, 0x17);
        //     wprintf(L"vmwrite(VMCS_32BIT_CONTROL_VMENTRY_INSTRUCTION_LENGTH, 0x%x);\n", vmread(VMCS_32BIT_CONTROL_VMENTRY_INSTRUCTION_LENGTH));
        // break;
        // }
        // }
        // vmwrite(0x2018, 0x1); // VMFUNC_CTRLS
        for (int i = 0; i < vmcs_num; i++)
        {
            if (!(
                    (vmcs_index[i] & 0x0f00) == 0xc00 || (vmcs_index[i] & 0x0f00) == 0x400
                    // (vmcs_index[i] & 0x0f00) == 0x400
                    ))
            {
                ;
                // wprintf(L"vmwrite(0x%x,0x%x);\n", vmcs_index[i], vmread(vmcs_index[i]));
                // vmwrite(vmcs_index[i],restore_vmcs[i]);
            }
        }
        //     if (loop_count == 2)
        // vmwrite(0x4000, 0x1);
        // wprintf(L"vmwrite(0x401e, 0x%x);\n", vmread(0x401e)&(1<<13));
        // wprintf(L"vmwrite(0x4000, 0x%x);\n", vmread(0x4000));
        // wprintf(L"vmwrite(0x%x, 0x%x);\n",vmcs_index[tmp], vmread(vmcs_index[tmp]));
        // wprintf(L"vmwrite(0x4002, 0x%x);\n", vmread(0x4002));
        // wprintf(L"vmwrite(0x4016, 0x%x);\n", vmread(0x4016));
        // wprintf(L"vmwrite(0x6002, 0x%x);\n", vmread(0x6002));
        // wprintf(L"vmwrite(0x6006, 0x%x);\n", vmread(0x6006));
        // wprintf(L"11:0x%x, 10-8:0x%x, 7-0:0x%x\n", (vmread(0x4016)>>11)&1, (vmread(0x4016)>>8)&0x7, vmread(0x4016)&0xff);

        // wprintf(L"vmwrite(0x401e, 0x%x);\n", vmread(0x401e));

        // wprintf(L"vmwrite(0x%x,0x%x);\n", 0x4826, vmread(0x4826));

        // vmwrite(0x681E, (uint64_t)guest_entry);
        // vmwrite(0x440c, 0);
        // vmwrite(0x4826, 1); // HLT
        // vmwrite(0x4826, 3); // SIPI
        // wprintf(L"input_buf[1024] = 0x%x\n", input_buf[1024]);
        // wprintf(L"input_buf[512] = 0x%x\n", input_buf[512]);
        // wprintf(L"input_buf[256] = 0x%x\n", input_buf[256]);
        // wprintf(L"input_buf[8] = 0x%x\n", input_buf[8]);
        // wprintf(L"input_buf[0] = 0x%x\n", input_buf[0]);
        // wprintf(L"vmwrite(0x812, 0x%x);\n", vmread(0x812));
        // vmwrite(0x812,0);
        windex = vmcs_index[input_buf[0x500 / 2] % vmcs_num]; // at 0x500 byte
        wvalue = ((uint64_t *)(input_buf) + 0x508 / 8)[0];    // 0x508
        // for(int i = 0; i < 1000; i+=8){
        //     wprintf(L"%x: %x\n",0x508+i,((uint64_t *)(input_buf)+(0x508+i)/8)[0]);
        // }
        index_count = 0x510 / 2;
        prev_val = vmread(windex);
        prev_ind = windex;
        next_val = wvalue;
        // wprintf(L"wvalue = 0x%x\n", wvalue);
        // wvalue = input_buf[152*4+1];
        if (windex < 0x2000)
        { // 16b
            // wvalue = (uint16_t)((uint16_t)prev_val^((uint16_t)wvalue));
            wvalue = (uint16_t)prev_val ^ (wvalue & (0xf << (input_buf[0x502 / 2] % 13)));
        }
        else if (windex < 0x4000)
        { // 64b
            wvalue = (uint64_t)prev_val ^ (wvalue & (0xf << (input_buf[0x502 / 2] % 61)));
            // wvalue = (uint64_t)((uint64_t)prev_val^((uint64_t)wvalue));
        }
        else if (windex < 0x6000)
        { // 32b
            wvalue = (uint32_t)prev_val ^ (wvalue & (0xf << (input_buf[0x502 / 2] % 29)));
            // wvalue = (uint32_t)((uint32_t)prev_val^((uint32_t)wvalue));
        }
        else
        { // 64b
            wvalue = (uint64_t)prev_val ^ (wvalue & (0xf << (input_buf[0x502 / 2] % 61)));
            // wvalue = (uint64_t)((uint64_t)prev_val^((uint64_t)wvalue));
        }
        // if (windex < 0x2000) { // 16b
        //     wvalue = (uint16_t)((uint16_t)prev_val&((uint16_t)wvalue));
        // } else if (windex < 0x4000) { // 64b
        //     wvalue = (uint64_t)((uint64_t)prev_val&((uint64_t)wvalue));
        // } else if (windex < 0x6000) { // 32b
        //     wvalue = (uint32_t)((uint32_t)prev_val&((uint32_t)wvalue));
        // } else { // 64b
        //     wvalue = (uint64_t)((uint64_t)prev_val&((uint64_t)wvalue));
        // }
        if ((windex & 0x0f00) != 0xc00)
        {
            if (windex == 0x400e || windex == 0x681c || windex == 0x681e || windex == 0x6816 || windex == 0x681E || windex == 0x2800 || windex == 0x2000 || windex == 0x2002 || windex == 0x2004 || windex == 0x2006 || windex == 0x2008 || windex == 0x200a || windex == 0x200c || windex == 0x200e || windex == 0x2012 || windex == 0x2014 || windex == 0x2016 || windex == 0x2024 || windex == 0x2026 || windex == 0x2028 || windex == 0x202a)
            {
                ;
            }
            else
            {
                // wprintf(L"vmwrite(0x%x,0x%x);\n",windex,vmread(windex));
                if (input_buf[index_count] % 2)
                {
                    // wprintf(L"vmwrite(0x%x,0x%x);\n",windex,vmread(windex));
                    vmwrite(windex, wvalue);
                    wprintf(L"vmwrite(0x%x,0x%x);\n", windex, wvalue);
                }
            }
        }
        for (int i = 0; i < vmcs_num; i++)
        {
            if (!(
                    (vmcs_index[i] & 0x0f00) == 0xc00 || (vmcs_index[i] & 0x0f00) == 0x400
                    // (vmcs_index[i] & 0x0f00) == 0x400
                    ))
            {
                ;
                // wprintf(L"vmwrite(0x%x,0x%x);\n", vmcs_index[i], vmread(vmcs_index[i]));
                // vmwrite(vmcs_index[i],restore_vmcs[i]);
            }
        }

        // vmwrite(0x681E, (uint64_t)guest_entry);
        // vmwrite(0x440c, 0);

        // if(current_evmcs) for(int i=0; i < vmcs_num; i++){
        //     if(current_evmcs)
        //         evmcs_vmwrite(vmcs_index[i],vmread(vmcs_index[i]));
        //     // wprintf(L"vmwrite(0x%x, 0x%x);\n", vmcs_index[i], vmread(vmcs_index[i]));
        // }
        if (current_evmcs)
        {
            /* HOST_RIP */
            current_evmcs->hv_clean_fields &= ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_HOST_GRP1;
            /* HOST_RSP */
            current_evmcs->hv_clean_fields &= ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_HOST_POINTER;
        }
        else
        {
            vmwrite(0x681E, (uint64_t)guest_entry);
            vmwrite(0x440c, 0);
        }
        // current_evmcs->revision_id = 1;
        // vmwrite(0x681E, (uint64_t)guest_entry);
        shiftcount = 0;
        // input_buf[0]=0;
        asm volatile("vmresume\n\t");
        wprintf(L"VMRESUME failed: \r\n");

        // // fuzz_vmcs:
        // for(int i = 0; i < 8; i++){
        //     if (windex < 0x2000) {
        //         if (i>1) break;
        //         wvalue = (uint16_t)((uint16_t)prev_val^(wvalue&(0xff<<(i*8))));
        //     } else if (windex < 0x4000) {
        //         wvalue = (uint64_t)((uint64_t)prev_val^(wvalue&(0xff<<(i*8))));
        //     } else if (windex < 0x6000) {
        //         if (i>4) break;
        //         wvalue = (uint32_t)((uint32_t)prev_val^(wvalue&(0xff<<(i*8))));
        //     } else {
        //         wvalue = (uint64_t)((uint64_t)prev_val^(wvalue&(0xff<<(i*8))));
        //     }
        //     if((windex&0x0f00) != 0xc00){
        //         if(windex == 0x400e || windex == 0x681c || windex == 0x6816){
        //             ;
        //         }
        //         else{
        //             vmwrite(windex, wvalue);
        //             // wprintf(L"vmwrite(0x%x,0x%x);\n",windex,vmread(windex));
        //             wprintf(L"vmwrite(0x%x,0x%x);\n",windex,wvalue);
        //         }
        //     }

        //     vmwrite(0x681E, (uint64_t)guest_entry);
        //     vmwrite(0x440c, 0);

        //     if(current_evmcs) for(int j=0; j < vmcs_num; j++){
        //         if(current_evmcs)
        //             evmcs_vmwrite(vmcs_index[j],vmread(vmcs_index[j]));
        //         // wprintf(L"vmwrite(0x%x, 0x%x);\n", vmcs_index[i], vmread(vmcs_index[i]));
        //     }
        //     if(current_evmcs){
        //         /* HOST_RIP */
        //         current_evmcs->hv_clean_fields &= ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_HOST_GRP1;
        //         /* HOST_RSP */
        //         current_evmcs->hv_clean_fields &= ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_HOST_POINTER;
        //     }
        //     asm volatile("vmresume\n\t");
        //     wprintf(L"VMRESUME failed: \r\n");
        // }

        guest_hang = 1;
        for (int i = 0; i < vmcs_num; i++)
        {
            {
                // wprintf(L"vmwrite(0x%x,0x%x);\n", vmcs_index[i], vmread(vmcs_index[i]));
                // vmwrite(vmcs_index[i],restore_vmcs[i]);
                // if(current_evmcs){
                //     evmcs_vmwrite(vmcs_index[i],vmread(restore_vmcs[i]));
                // }
            }
        }
        if (current_evmcs)
        {
            /* HOST_RIP */
            current_evmcs->hv_clean_fields &= ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_HOST_GRP1;
            /* HOST_RSP */
            current_evmcs->hv_clean_fields &= ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_HOST_POINTER;
            // current_evmcs->revision_id = 1;
        }

        for (int i = 0; i < 100; i++)
        {
            exec_fuzz();
        }

        asm volatile("vmresume\n\t");
        wprintf(L"VMRESUME failed: \r\n");

        uint64_t errnum = vmread(0x4400);
        if (current_evmcs)
        {
            evmcs_vmread(0x4400, &errnum);
        }
        wprintf(L"Error Number is %d\r\n", errnum);
        for (int i = 0; i < vmcs_num; i++)
        {
            if (!(
                    // (vmcs_index[i] & 0x0f00) == 0xc00
                    // || (vmcs_index[i] & 0x0f00) == 0x400
                    (vmcs_index[i] & 0x0f00) == 0x400))
            {
                // wprintf(L"vmwrite(0x%x,0x%x);\n", vmcs_index[i], vmread(vmcs_index[i]));
            }
        }
        __builtin_longjmp(env, 1);
        // return;
    }
}

void __host_entry(void);
void _host_entry(void)
{

    asm volatile(
        "__host_entry:\n\t"
        "call host_entry\n\t"
        "vmresume\n\t"
        "loop: jmp loop\n\t");
}

char vmxon_region_L2[4096] __attribute__((aligned(4096)));
struct __attribute__((__packed__, aligned(64))) xsave_header
{
    uint64_t xstate_bv;
    uint64_t reserved[2];
};

struct fpu_state_buffer
{
    struct xsave_header header;
    char buffer[];
};
int l2_count;
_Noreturn void guest_entry(void)
{
    // vmread(0xffffffff);
    // vmread(0x20000);

    // asm volatile("xsaves");
    // uint32_t error;
    // uint32_t revision_id = rdmsr(0x480);
    // uint32_t *ptr = (uint32_t *)vmxon_region_L2;
    // // vmxonptr = (uintptr_t)ptr;
    // ptr[0] = revision_id;
    // asm volatile ("vmxon %1" : "=@ccbe" (error) : "m" (ptr));
    // asm volatile ("vmxoff");
    // asm volatile ("vmresume");
    // vmread(0x4000);
    // asm volatile ("mov 0xffff, %eax");
    // asm volatile ("mov 0xffff, %edx");
    // uint32_t a = input_buf[index_count];
    // asm volatile("umwait %0"::"r"(a));
    // uint64_t b = input_buf[index_count];
    // asm volatile ("mov 0xffffffff, %eax\r\n");
    // asm volatile ("mov 0xffffffff, %edx\r\n");
    // asm volatile("tpause %0"::"r"(a));
    while (1)
    {

        //     uint64_t aa;
        //     // aa = loop_count;
        //         asm volatile ("mov %0, %%rax"::"d" (0xffffffffffffffff):);
        // asm volatile("xsaves %0":"+m"(aa));
        // asm volatile ("vmfunc":::);
        // if(current_evmcs)
        // uint16_t a = input_buf[1000];
        // if (a==0){
        // if (current_evmcs){
        // if (a==0xdead){
        if (loop_count == 0)
        {
            // loop_count[0]=100;
            vmcall(1);
        }
        // if (input_buf[0]){
        //     l2_count+=1;
        //     vmcall(1);
        // }
        //     int index=0,edx=0,ecx=0;
        //     __asm__ __volatile__ (
        //   "xsetbv"
        //   :
        //   : "a" (index), "d" (edx), "c" (ecx)
        // );
        // vmread(0xffffffff);
        // vmwrite(0xffffffff,0);

        // asm volatile ("vmlaunch"); // 61
        // uint64_t zero;
        // asm volatile ("rdseed %0" : "+c" (zero) : : "%rax"); // 61
        // uint32_t index= 0x2004;
        // uint64_t value = get64b(index_count);
        // asm volatile ("vmwrite %%rdx, %%rax"
        // 	:
        // 	: "a" (index), "d" (value)
        // 	: "cc", "memory");
        // asm volatile("clts");
        // asm volatile ("movq %0, %%cr0" : "+c" (value) : : "%rax");
        // asm volatile ("movq %0, %%cr3" : "+c" (value) : : "%rax");
        // asm volatile ("movq %0, %%cr0" : "+c" (value) : : "%rax");
        // asm volatile ("movq %0, %%cr4" : "+c" (value) : : "%rax");
        // asm volatile ("movq %0, %%cr8" : "+c" (value) : : "%rax");
        // asm volatile ("movq %%cr0, %0" : "=c" (zero) : : "%rbx");
        // asm volatile ("movq %%cr3, %0" : "=c" (zero) : : "%rbx");
        // asm volatile ("movq %%cr4, %0" : "=c" (zero) : : "%rbx");
        // asm volatile ("movq %%cr8, %0" : "=c" (zero) : : "%rbx");
        // __invpcid(3, 0, 3); // 58 vmexit sometimes hang
        //     struct fpu_state_buffer fsb;
        //         asm volatile("xsave %0": "=m"(fsb):: "memory");
        //         asm volatile("xsave %0":: "m"(fsb): "memory");
        // uint64_t aa = loop_count;
        //     asm volatile ("mov %0, %%rcx"::"d" (aa):);
        // asm volatile ("mov 0, %eax");
        // asm volatile ("vmfunc":::);
        // asm volatile ("mov %0, %%dx" ::"r" (input_buf[index_count++]));
        // asm volatile ("mov %0, %%eax" ::"r" (get32b(index_count)));
        // index_count+=2;
        // asm volatile ("out %eax, %dx");
        //         asm volatile ("mov %0, %%dx" ::"r" (input_buf[index_count++]));
        // asm volatile("in %dx, %eax");
        uint16_t instr_selector;
        for (int i = 0; i < 200; i++)
        {
            instr_selector = exec_fuzz_L2();
        }

        // tmp++;

        vmcall(1);
    }

    // for(int i = 0; i < 200; i++){
    // vmcall(1);
    // l++;
    // }
    // __builtin_longjmp(env, 1);

    vmcall(0);
    while (1)
        ;
}

struct registers
{
    uint16_t cs, ds, es, fs, gs, ss, tr, ldt;
    uint32_t rflags;
    uint64_t cr0, cr3, cr4;
    uint64_t ia32_efer, ia32_feature_control;
    struct
    {
        uint16_t limit;
        uint64_t base;
    } __attribute__((packed)) gdt, idt;
    // attribute "packed" requires -mno-ms-bitfields
};

void save_registers(struct registers *regs)
{
    asm volatile("mov %%cr0, %0"
                 : "=r"(regs->cr0));
    asm volatile("mov %%cr3, %0"
                 : "=r"(regs->cr3));
    asm volatile("mov %%cr4, %0"
                 : "=r"(regs->cr4));
    regs->ia32_efer = rdmsr(0xC0000080);
    asm volatile("pushf; pop %%rax"
                 : "=a"(regs->rflags));
    asm volatile("mov %%cs, %0"
                 : "=m"(regs->cs));
}

void print_registers(struct registers *regs)
{
    wprintf(L"CR0: %016x, CR3: %016x, CR4: %016x\r\n", regs->cr0, regs->cr3, regs->cr4);
    wprintf(L"RFLAGS: %016x\r\n", regs->rflags);
    wprintf(L"CS: %04x\r\n", regs->cs);
    wprintf(L"IA32_EFER: %016x\r\n", regs->ia32_efer);
    wprintf(L"IA32_FEATURE_CONTROL: %016x\r\n", rdmsr(0x3a));
}

char host_stack[4096] __attribute__((aligned(4096)));
char vp_assist[4096] __attribute__((aligned(4096)));
char guest_stack[4096] __attribute__((aligned(4096)));
char tss[4096] __attribute__((aligned(4096)));
char io_bitmap_a[4096] __attribute__((aligned(4096)));
char io_bitmap_b[4096] __attribute__((aligned(4096)));
// char msr_bitmap[4096] __attribute__ ((aligned (4096)));
char msr_bitmap[4096] __attribute__((aligned(4096)));
char vmread_bitmap[4096] __attribute__((aligned(4096)));
char vmwrite_bitmap[4096] __attribute__((aligned(4096)));
char apic_access[4096] __attribute__((aligned(4096)));
char virtual_apic[4096] __attribute__((aligned(4096)));
uint64_t eptp_list[512] __attribute__((aligned(4096)));
uint64_t pml[512] __attribute__((aligned(4096)));
uint32_t excep_info_area[6] __attribute__((aligned(4096)));
// char msr_load[8192] __attribute__ ((aligned (4096)));
// char msr_store[8192] __attribute__ ((aligned (4096)));
// char vmentry_msr_load[8192] __attribute__ ((aligned (4096)));

uint64_t posted_int_desc[8] __attribute__((aligned(4096)));

struct MSR_BITMAP
{
    uint64_t MSR_READ_LO[128];
    uint64_t MSR_READ_HI[128];
    uint64_t MSR_WRITE_LO[128];
    uint64_t MSR_WRITE_HI[128];
} __attribute__((aligned(4096)));

void *
memset(void *dest, int val, int len)
{
    unsigned char *ptr = dest;
    while (len-- > 0)
        *ptr++ = val;
    return dest;
}

//   uint64_t pdp_table_2[512] __attribute__ ((aligned (4096)));;
//   uint64_t page_directory_2[512][512] __attribute__ ((aligned (4096)));;
// }
uint64_t *SetupIdentityPageTable()
{
    pml4_table[0] = (uint64_t)&pdp_table[0] | 0x407;
    pml4_table_2[0] = (uint64_t)&pdp_table[0] | 0x407;
    for (int i_pdpt = 0; i_pdpt < 512; ++i_pdpt)
    {
        pdp_table[i_pdpt] = (uint64_t)&page_directory[i_pdpt] | 0x407;
        for (int i_pd = 0; i_pd < 512; ++i_pd)
        {
            page_directory[i_pdpt][i_pd] = (i_pdpt * kPageSize1G + i_pd * kPageSize2M) | 0x4f7;
        }
    }
    return &pml4_table[0];
    //   SetCR3(reinterpret_cast<uint64_t>(&pml4_table[0]));
}
// uint64_t page_dir_ptr_tab[4] __attribute__((aligned(0x20)));
// uint64_t page_dir[512] __attribute__((aligned(0x1000)));  // must be aligned to page boundary

struct hv_enlightened_vmcs *current_evmcs;

EFI_STATUS
EFIAPI
EfiMain(
    IN EFI_HANDLE ImageHandle,
    IN EFI_SYSTEM_TABLE *_SystemTable)
{
    uint32_t error;
    struct registers regs;

    SystemTable = _SystemTable;

    wprintf(L"Starting VMXbench ...\r\n");

    uint8_t ivshm_dev = 0;
    uint8_t dev = 0;
    for (dev = 0; dev < 32; dev++)
    {
        uint16_t vendor_id = ReadVendorId(0, dev, 0);
        if (vendor_id == 0x1af4)
        {
            ivshm_dev = dev;
            wprintf(L"bus:%d, dev:%d, func:%d, vendor : %04x\r\n", 0, dev, 0, vendor_id);
            break;
        }
    }
    uint32_t ecx, ebx, edx;
    uint32_t eax;
    asm volatile("cpuid"
                 : "=a"(eax), "=c"(ecx), "=b"(ebx), "=d"(edx)
                 : "a"(0x40000080)
                 :);
    wprintf(L" ecx: 0x%x", ecx);
    wprintf(L" ebx: 0x%x", ebx);
    wprintf(L" edx: 0x%x\n", edx);
    if (ebx == 0x7263694D && ecx == 0x666F736F && edx == 0x53562074)
    { // Microsoft SV?
        wprintf(L" evmcs enable\n");
        uint64_t vp_addr = (uint64_t)vp_assist | 0x1;
        wrmsr(0x40000073, vp_addr);
        struct hv_vp_assist_page *current_vp_assist = (void *)vp_assist;
        current_vp_assist->current_nested_vmcs = (uint64_t)vmcs;
        current_vp_assist->enlighten_vmentry = 1;
        current_evmcs = (struct hv_enlightened_vmcs *)vmcs;
    }

    // wprintf(L"%d, dev %d\r\n",(ivshm_dev==dev),ivshm_dev);
    // ivshm_dev++;
    uintptr_t bar2 = ReadBar(0, ivshm_dev, 0, 2);
    wprintf(L"bar2:0x%x\r\n", bar2);
    input_buf = (void *)(bar2);

    // for(int i = 0; i < 20; i++){
    // wprintf(L"buf[%d] = %x\r\n", i,input_buf[i]);}
    input_buf[3000] = 0xdead;
    // return 1;
    SetupIdentityPageTable();
    SystemTable->BootServices->SetWatchdogTimer(0, 0, 0, NULL);

    // check the presence of VMX support
    asm volatile("cpuid"
                 : "=c"(ecx)
                 : "a"(1)
                 : "ebx", "edx");
    wprintf(L"cpuid(eax=1): 0x%x\n", ecx);

    if ((ecx & 0x20) == 0) // CPUID.1:ECX.VMX[bit 5] != 1
        goto error_vmx_not_supported;
    wprintf(L"VMX is supported\r\n");

    // enable VMX
    wprintf(L"Enable VMX\r\n");
    asm volatile("mov %%cr4, %0"
                 : "=r"(regs.cr4));
    regs.cr4 |= 0x2000; // CR4.VME[bit 13] = 1
    asm volatile("mov %0, %%cr4" ::"r"(regs.cr4));

    // enable VMX operation
    wprintf(L"Enable VMX operation\r\n");
    regs.ia32_feature_control = rdmsr(0x3a);
    if ((regs.ia32_feature_control & 0x1) == 0)
    {
        regs.ia32_feature_control |= 0x5; // firmware should set this
        wrmsr(0x3a, regs.ia32_feature_control);
    }
    else if ((regs.ia32_feature_control & 0x4) == 0)
        goto error_vmx_disabled;

    // apply fixed bits to CR0 & CR4
    uint64_t apply_fixed_bits(uint64_t reg, uint32_t fixed0, uint32_t fixed1)
    {
        reg |= rdmsr(fixed0);
        reg &= rdmsr(fixed1);
        return reg;
    }
    asm volatile("mov %%cr0, %0"
                 : "=r"(regs.cr0));
    regs.cr0 = apply_fixed_bits(regs.cr0, 0x486, 0x487);
    asm volatile("mov %0, %%cr0" ::"r"(regs.cr0));
    asm volatile("mov %%cr4, %0"
                 : "=r"(regs.cr4));
    wprintf(L" cr4 0x%x\n", regs.cr4);
    regs.cr4 = apply_fixed_bits(regs.cr4, 0x488, 0x489);
    asm volatile("mov %0, %%cr4" ::"r"(regs.cr4));
    wprintf(L" cr4 0x%x\n", regs.cr4);

    // enter VMX operation
    wprintf(L"Enter VMX operation\r\n");
    revision_id = rdmsr(0x480);
    uint32_t *ptr = (uint32_t *)vmxon_region;
    vmxonptr = (uintptr_t)ptr;
    ptr[0] = revision_id;
    asm volatile("vmxon %1"
                 : "=@ccbe"(error)
                 : "m"(ptr));
    if (error)
        goto error_vmxon;
    asm volatile("vmxoff");
    asm volatile("vmxon %1"
                 : "=@ccbe"(error)
                 : "m"(ptr));
    // asm volatile ("vmxon %1" : "=@ccbe" (error) : "m" (ptr));
    if (error)
        goto error_vmxon;
    // initialize VMCS
    wprintf(L"Initialize VMCS\r\n");

    __builtin_memset(vmcs, 0, 4096);
    ptr = (uint32_t *)vmcs;
    ptr[0] = revision_id;
    if (!current_evmcs)
    {
        asm volatile("vmclear %1"
                     : "=@ccbe"(error)
                     : "m"(ptr));
        if (error)
            goto error_vmclear;
        asm volatile("vmptrld %1"
                     : "=@ccbe"(error)
                     : "m"(ptr));
        if (error)
            goto error_vmptrld;

        asm volatile("vmclear %1"
                     : "=@ccbe"(error)
                     : "m"(ptr));
        if (error)
            goto error_vmclear;
        asm volatile("vmptrld %1"
                     : "=@ccbe"(error)
                     : "m"(ptr));
        if (error)
            goto error_vmptrld;
    }

    // vmcall_with_vmcall_number(13);
    // initialize control fields
    uint32_t apply_allowed_settings(uint32_t value, uint64_t msr_index)
    {
        uint64_t msr_value = rdmsr(msr_index);
        value |= (msr_value & 0xffffffff);
        value &= (msr_value >> 32);
        return value;
    }

    void vmwrite_gh(uint32_t guest_id, uint32_t host_id, uint64_t value)
    {
        vmwrite(guest_id, value);
        vmwrite(host_id, value);
    }

    // 16-Bit Guest and Host State Fields
    asm volatile("mov %%es, %0"
                 : "=m"(regs.es));
    asm volatile("mov %%cs, %0"
                 : "=m"(regs.cs));
    asm volatile("mov %%ss, %0"
                 : "=m"(regs.ss));
    asm volatile("mov %%ds, %0"
                 : "=m"(regs.ds));
    asm volatile("mov %%fs, %0"
                 : "=m"(regs.fs));
    asm volatile("mov %%gs, %0"
                 : "=m"(regs.gs));
    asm volatile("sldt %0"
                 : "=m"(regs.ldt));
    asm volatile("str %0"
                 : "=m"(regs.tr));
    vmwrite_gh(0x0800, 0x0c00, regs.es); // ES selector
    vmwrite_gh(0x0802, 0x0c02, regs.cs); // CS selector
    vmwrite_gh(0x0804, 0x0c04, regs.ss); // SS selector
    vmwrite_gh(0x0806, 0x0c06, regs.ds); // DS selector
    vmwrite_gh(0x0808, 0x0c08, regs.fs); // FS selector
    vmwrite_gh(0x080a, 0x0c0a, regs.gs); // GS selector

    vmwrite(0x080c, regs.ldt);           // Guest LDTR selector
    vmwrite_gh(0x080e, 0x0c0c, regs.tr); // TR selector
    vmwrite(0x0c0c, 0x08);               // dummy TR selector for real hardware

    // 64-Bit Guest and Host State Fields
    vmwrite(0x2802, 0); // Guest IA32_DEBUGCTL
    regs.ia32_efer = rdmsr(0xC0000080);
    vmwrite_gh(0x2806, 0x2c02, regs.ia32_efer); // IA32_EFER
    wprintf(L" ia32_efer 0x%x\n", regs.ia32_efer);
    // 32-Bit Guest and Host State Fields
    asm volatile("sgdt %0"
                 : "=m"(regs.gdt));
    asm volatile("sidt %0"
                 : "=m"(regs.idt));

    vmwrite(0x4800, get_seg_limit(regs.es));  // Guest ES limit
    vmwrite(0x4802, get_seg_limit(regs.cs));  // Guest CS limit
    vmwrite(0x4804, get_seg_limit(regs.ss));  // Guest SS limit
    vmwrite(0x4806, get_seg_limit(regs.ds));  // Guest DS limit
    vmwrite(0x4808, get_seg_limit(regs.fs));  // Guest FS limit
    vmwrite(0x480a, get_seg_limit(regs.gs));  // Guest GS limit
    vmwrite(0x480c, get_seg_limit(regs.ldt)); // Guest LDTR limit
    uint32_t tr_limit = get_seg_limit(regs.tr);
    if (tr_limit == 0)
        tr_limit = 0x0000ffff;
    vmwrite(0x480e, tr_limit);                       // Guest TR limit
    vmwrite(0x4810, regs.gdt.limit);                 // Guest GDTR limit
    vmwrite(0x4812, regs.idt.limit);                 // Guest IDTR limit
    vmwrite(0x4814, get_seg_access_rights(regs.es)); // Guest ES access rights
    vmwrite(0x4816, get_seg_access_rights(regs.cs)); // Guest CS access rights
    vmwrite(0x4818, get_seg_access_rights(regs.ss)); // Guest SS access rights
    vmwrite(0x481a, get_seg_access_rights(regs.ds)); // Guest DS access rights
    vmwrite(0x481c, get_seg_access_rights(regs.fs)); // Guest FS access rights
    vmwrite(0x481e, get_seg_access_rights(regs.gs)); // Guest GS access rights
    uint32_t ldtr_access_rights = get_seg_access_rights(regs.ldt);
    if (ldtr_access_rights == 0)
        ldtr_access_rights = 0x18082;
    vmwrite(0x4820, ldtr_access_rights); // Guest LDTR access rights
    uint32_t tr_access_rights = get_seg_access_rights(regs.tr);
    if (tr_access_rights == 0)
        tr_access_rights = 0x0808b;
    vmwrite(0x4822, tr_access_rights); // Guest TR access rights

    vmwrite(0x6000, 0xffffffffffffffff); // CR0 guest/host mask
    vmwrite(0x6002, 0xffffffffffffffff); // CR4 guest/host mask
    vmwrite(0x6004, ~regs.cr0);          // CR0 read shadow
    vmwrite(0x6006, ~regs.cr4);          // CR4 read shadow
    // Natual-Width Control Fields
    asm volatile("mov %%cr3, %0"
                 : "=r"(regs.cr3));
    vmwrite_gh(0x6800, 0x6c00, regs.cr0);
    // vmwrite(0x6800, regs.cr0&(~1));
    // wprintf(L" vmwrite(0x6800, 0x%x);\n", vmread(0x6800));
    // vmwrite(0x6c00, regs.cr0);
    vmwrite_gh(0x6802, 0x6c02, regs.cr3);
    vmwrite_gh(0x6804, 0x6c04, regs.cr4);
    wprintf(L" cr3 0x%x\n", regs.cr3);
    wprintf(L" cr0 pageing 0x%x\n", regs.cr0 >> 31);

    // wprintf(L"cr0 %0x, cr4 %0x\r\n", regs.cr0,regs.cr4);

    vmwrite(0x6806, get_seg_base(regs.es));  // es base
    vmwrite(0x6808, get_seg_base(regs.cs));  // cs base
    vmwrite(0x680a, get_seg_base(regs.ss));  // ss base
    vmwrite(0x680c, get_seg_base(regs.ds));  // ds base
    vmwrite(0x680e, get_seg_base(regs.fs));  // fs base
    vmwrite(0x6810, get_seg_base(regs.gs));  // gs base
    vmwrite(0x6812, get_seg_base(regs.ldt)); // LDTR base
    vmwrite(0x6814, (uint64_t)tss);          // TR base

    vmwrite_gh(0x6816, 0x6C0C, regs.gdt.base); // GDTR base
    vmwrite_gh(0x6818, 0x6C0E, regs.idt.base); // IDT base

    vmwrite(0x6C14, (uint64_t)&host_stack[sizeof(host_stack)]);   // HOST_RSP
    vmwrite(0x6C16, (uint64_t)__host_entry);                      // Host RIP
    vmwrite(0x681C, (uint64_t)&guest_stack[sizeof(guest_stack)]); // GUEST_RSP
    vmwrite(0x681E, (uint64_t)guest_entry);                       // Guest RIP

    asm volatile("pushf; pop %%rax"
                 : "=a"(regs.rflags));
    regs.rflags &= ~0x200ULL; // clear interrupt enable flag
    vmwrite(0x6820, regs.rflags);

    // *****EDIT VMCS FIELD*****
    // page_dir_ptr_tab[0] = (uint64_t)&page_dir | 1; // set the page directory into the PDPT and mark it present
    // for(int i = 0; i < 512; i++){
    //     page_dir[0] = 0b10000011; //Address=0, 2MIB, RW and present
    // }
    // vmwrite(0x280a, page_directory[0]&~());
    // vmwrite(0x280c, page_directory[1]);
    // vmwrite(0x280e, page_directory[2]);
    // vmwrite(0x2810, page_directory[3]);
    vmwrite(0x802, 0);
    memset(&io_bitmap_a, 0xaa, sizeof(io_bitmap_a));
    vmwrite(0x2000, (uint64_t)io_bitmap_a);
    memset(&io_bitmap_b, 0x55, sizeof(io_bitmap_b));
    vmwrite(0x2002, (uint64_t)io_bitmap_b);

    // set up msr bitmap to vmexit from L2
    memset(&msr_bitmap, 0xff, sizeof(msr_bitmap));
    vmwrite(0x2004, (uint64_t)msr_bitmap);

    for (int i = 0; i < 512; i++)
    {
        msr_store[i * 2] = 0x10;
        msr_store[i * 2 + 1] = 0x10;
        msr_load[i * 2] = 0x10;
        msr_load[i * 2 + 1] = 0x20;
        // vmentry_msr_load[i*2] = (uint64_t)0xC0000100;
        vmentry_msr_load[i * 2] = (uint64_t)0x10;
        vmentry_msr_load[i * 2 + 1] = (uint64_t)0x10;
        // vmentry_msr_load[i*2+1] = (uint64_t)rdmsr(0x40000073);
    }

    // uintptr_t msr_store_addr = (uintptr_t)msr_store;
    // uintptr_t msr_load_addr = (uintptr_t)msr_load;
    // uintptr_t vmentry_msr_load_addr = (uintptr_t)vmentry_msr_load;
    for (int i = 0; i < 8; i++)
    {
        posted_int_desc[i] = (uint64_t)get64b(i);
    }
    uintptr_t posted_int_desc_addr = (uintptr_t)posted_int_desc;
    vmwrite(0x2006, (uint64_t)msr_store);
    vmwrite(0x2008, (uint64_t)msr_load);
    vmwrite(0x200a, (uint64_t)vmentry_msr_load);
    vmwrite(0x400e, 511);
    vmwrite(0x4010, 511);
    vmwrite(0x4014, 511);

    vmwrite(0x200c, (uint64_t)vmxonptr);
    vmwrite(0x200e, (uint64_t)pml);
    vmwrite(0x2010, (uint64_t)-1);
    vmwrite(0x2012, (uint64_t)virtual_apic);
    vmwrite(0x2014, (uint64_t)apic_access);
    // vmwrite(0x2012, (uint64_t)virtual_apic);
    // vmwrite(0x2014, (uint64_t)apic_access);
    vmwrite(0x2016, (uint64_t)posted_int_desc);

    // uintptr_t VIRTUAL_APIC_ADDR = (uintptr_t)virtual_apic;
    // uintptr_t vtpr_ptr = vmread(0x2012) + 0x80;
    // uint32_t *vtpr = (uint32_t *)vtpr_ptr;
    // wprintf(L"0x2012:%x\r\nvtpr: %x\r\n", vmread(0x2012),vtpr[0]);
    for (int i = 0; i < 4096; i++)
    {
        virtual_apic[i] = 0xff;
    }
    virtual_apic[0x16] = 0x16;
    virtual_apic[0x80] = 0x80;
    // uintptr_t APIC_ACCESS_ADDR = (uintptr_t)apic_access;

    uint64_t eptp = (uint64_t)pml4_table;
    uint64_t eptp2 = (uint64_t)pml4_table_2;
    // wprintf(L"eptp 0x%x\n", eptp);
    // eptp |= 0x18;
    eptp |= 0x5e; // WB
    // eptp |= 0x58; // UC
    eptp2 |= 0x5e;
    // wprintf(L"eptp 0x%x\n", eptp);
    vmwrite(0x201a, eptp);

    eptp_list[0] = eptp;
    eptp_list[1] = eptp2;
    uint64_t eptp_list_addr = (uint64_t)eptp_list;
    vmwrite(0x2024, eptp_list_addr);

    vmwrite(0x2026, (uint64_t)vmread_bitmap);
    vmwrite(0x2028, (uint64_t)vmwrite_bitmap);
    vmwrite(0x202a, (uint64_t)excep_info_area);
    vmwrite(0x2032, 0xffffffffffffffff);
    vmwrite(0x202c, 0xffffffffffffffff);

    // memset(&msr_store, 0xff, sizeof(msr_store));
    // memset(&msr_load, 0xff, sizeof(msr_load));
    // memset(&vmentry_msr_load, 0xff, sizeof(vmentry_msr_load));

    uint32_t *shadow_ptr = (uint32_t *)shadow_vmcs2;
    shadow_ptr[0] = rdmsr(0x480) | BX_VMCS_SHADOW_BIT_MASK;
    vmwrite(0x2800, (uint64_t)shadow_vmcs2);

    vmwrite(0x482e, 0xffffffff);
    // vmwrite(0x482e,0x0);

    // vmwrite(0x2034,apply_allowed_settings(0x1,0x492));
    vmwrite(0x4004, 0x0);            // Exception bitmap
    vmwrite(0x4004, 0x1 << 14 | 14); // Exception bitmap

    vmwrite(0x0, 0xffff);

    vmwrite(0x4006, 0x0);
    vmwrite(0x4008, -1);
    vmwrite(0x400a, 0x0);

    // Pin-based VM-execution controls
    vmwrite(0x4000, apply_allowed_settings(0xff, 0x481));
    vmwrite(0x4000, apply_allowed_settings(0xf0, 0x481));

    // Primary processor-based VM-execution controls
    uint32_t ctrls2 = 0 |
                      1 << 2 |
                      1 << 3 |
                      1 << 7 |
                      1 << 9 |
                      1 << 10 |
                      1 << 11 |
                      1 << 12 |
                      1 << 15 |
                      1 << 16 |
                      1 << 19 |
                      1 << 20 |
                      1 << 21 |
                      // 1 << 22 |
                      1 << 23 |
                      1 << 24 |
                      1 << 25 |
                      // 1 << 27 |
                      1 << 28 |
                      1 << 29 |
                      1 << 30 |
                      1 << 31;
    vmwrite(0x4002, apply_allowed_settings(ctrls2, 0x482));
    // vmwrite(0x4002,apply_allowed_settings(0,0x482));

    uint32_t ctrls3 = 0 |
                      1 << 0 |
                      1 << 1 |
                      //   1 <<  2 |
                      1 << 3 |
                      1 << 4 |
                      1 << 5 |
                      1 << 6 |
                      1 << 7 |
                      1 << 8 |
                      1 << 9 |
                      1 << 10 |
                      1 << 11 |
                      1 << 12 |
                      1 << 13 |
                      1 << 14 |
                      //   1 << 15 |
                      1 << 16 |
                      1 << 17 |
                      1 << 18 |
                      1 << 19 |
                      1 << 20 |
                      1 << 22 |
                      1 << 23 |
                      1 << 24 |
                      1 << 25 |
                      1 << 26 |
                      1 << 27 |
                      1 << 28;
    vmwrite(0x401e, apply_allowed_settings(ctrls3, 0x48b));
    // vmwrite(0x401e, apply_allowed_settings(0, 0x48b));

    uint32_t exit_ctls = apply_allowed_settings(0xffffffff, 0x483);
    vmwrite(0x400c, exit_ctls); // VM-exit controls
    // vmwrite(0x400c, 0);      // VM-exit controls
    uint32_t entry_ctls = apply_allowed_settings(0xffffffff, 0x484);
    vmwrite(0x4012, entry_ctls & ~(1 << 15)); // VM-entry controls
    // vmwrite(0x4012, 0);     // VM-entry controls

    vmwrite(0x4824, 0x8);
    vmwrite(0x401c, 0xf);
    virtual_apic[0x80] = 0xff;
    // vmwrite(0x2806, 0x400); // IA32_EFER
    // vmwrite(0x6800, 0x33); // IA32_EFER
    // wprintf(L"vmwrite(0x2806, 0x%x);\n", vmread(0x2806));
    // wprintf(L"guest entry 0x%x\n",vmread(0x681e));
    // wprintf(L"vmwrite(0x4000, 0x%x);\n",vmread(0x4000));
    // wprintf(L"vmwrite(0x4000, 0x%x);\n",apply_allowed_settings(0,0x481));
    // wprintf(L"current evmcs 0x%x\n", current_evmcs);
    // uint64_t current_vmcsptr;
    // vmptrst(&current_vmcsptr);
    // wprintf(L"current_vmcsptr 0x%x\n", current_vmcsptr);
    // wprintf(L"revision id = 0x%x\n",VMXReadRevisionID((bx_phy_address) vmread(VMCS_64BIT_GUEST_LINK_POINTER)));
    vmwrite(0x2018, 0x1);        // VMFUNC_CTRLS
    vmwrite(0x812, 0x10);        // pml index
    vmwrite(0x4016, 0x00000000); // vmentry_intr_info
    // vmwrite(0x4002,vmread(0x4002)&~(1<<31));
    // vmwrite(0x401e,vmread(0x401e)|0xffffffff);
    // vmwrite(0x4016, 0x800006ea);
    wprintf(L"   ---VMCS CHECK START--   \r\n");
    enum VMX_error_code vmentry_check_failed = VMenterLoadCheckVmControls();
    if (!vmentry_check_failed)
    {
        wprintf(L"VMX CONTROLS OK!\r\n");
    }
    else
    {
        wprintf(L"VMX CONTROLS ERROR %0d\r\n", vmentry_check_failed);
    }
    vmentry_check_failed = VMenterLoadCheckHostState();
    if (!vmentry_check_failed)
    {
        wprintf(L"HOST STATE OK!\r\n");
    }
    else
    {
        wprintf(L"HOST STATE ERROR %0d\r\n", vmentry_check_failed);
    }
    uint64_t qualification;
    uint32_t is_error = VMenterLoadCheckGuestState(&qualification);
    if (!is_error)
    {
        wprintf(L"GUEST STATE OK!\r\n");
    }
    else
    {
        wprintf(L"GUEST STATE ERROR %0d\r\n", qualification);
        wprintf(L"GUEST STATE ERROR %0d\r\n", is_error);
    }

    for (int i = 0; i < vmcs_num; i++)
    {
        restore_vmcs[i] = vmread(vmcs_index[i]);
        // if(current_evmcs)
        //     evmcs_vmwrite(vmcs_index[i],restore_vmcs[i]);
        // wprintf(L"vmwrite(0x%x, 0x%x);\n", vmcs_index[i], restore_vmcs[i]);
    }

    if (current_evmcs)
    {
        current_evmcs->hv_clean_fields = 0;
        // current_evmcs->revision_id = 1;
    }
    input_buf[4003] = 0;
    // input_buf[1000] = 0xdead;
    // wprintf(L"vmwrite(0x4000, 0x%x);\n",vmread(0x4000));
    // vmwrite(0x401e,vmread(0x401e)|1<<15);
    wprintf(L"vmwrite(0x4002, 0x%x);\n", vmread(0x4002));
    wprintf(L"vmwrite(0x401e, 0x%x);\n", vmread(0x401e));
    if (vmread(0x401e) & (1 << 13))
        wprintf(L" vmfunc enable\n");
    // uint64_t a = rdmsr(0x00000da0);
    //  wrmsr(0x00000570,1);0x00000da0
    // asm volatile ("vmfunc":::);
    // uint64_t a = rdmsr(0x1b);
    // wrmsr(0x1b,a|1<<11);
    // wrmsr(0x1b,a&~(1<<11));

    // //     wprintf(L" vmentry x64 0x%x\n",vmread(0x00004012)>>9 &1);
    //     wprintf(L" a%x\n",a);

    // vmwrite(0x6804, vmread(6804)&~(1<<5));
    // ptr = (uint32_t *)vmcs;
    // ptr[0] = 0x1;
    // (void)rdmsr(0x48a);
    // for debug
    // for(uint32_t i = 0; i < 16; i++){
    //     uint64_t ans = rdmsr(0x480+i);
    //     wprintf(L"msr 0x%x : 0x%x\n", 0x480+i,ans);
    // }
    // for(int i = 0; i<11; i++){
    //     uint32_t a =0x40000000;
    //     asm volatile ("cpuid" : "=a"(a),"=c" (ecx),"=b" (ebx),"=d" (edx) :"a"(a+i): );
    //     wprintf(L"cpuid(0x%x)\n",0x40000000+i,a);
    //     wprintf(L" eax: 0x%x",a);
    //     wprintf(L" ecx: 0x%x",ecx);
    //     wprintf(L" ebx: 0x%x",ebx);
    //     wprintf(L" edx: 0x%x\n",edx);
    // }
    // for(int i = 0; i<11; i++){
    //     uint32_t a =0x40000080;
    //     asm volatile ("cpuid" : "=a"(a),"=c" (ecx),"=b" (ebx),"=d" (edx) :"a"(a+i): );
    //     wprintf(L"cpuid(0x%x)\n",0x40000080+i,a);
    //     wprintf(L" eax: 0x%x",a);
    //     wprintf(L" ecx: 0x%x",ecx);
    //     wprintf(L" ebx: 0x%x",ebx);
    //     wprintf(L" edx: 0x%x\n",edx);
    // }
    // wprintf(L"msr 0xc0000080 0x%x\n", rdmsr(0xc0000080));
    // wrmsr(0xc0000080,0x400);
    // wprintf(L"msr 0xc0000080 0x%x\n", rdmsr(0xc0000080));
    // wprintf(L"vmwrite(0x2806, 0x%x);\n", vmread(0x2806));
    // wprintf(L"vmwrite(0x6800, 0x%x);\n", vmread(0x6800));
    // wprintf(L"vmwrite(0x681c, 0x%x);\n", vmread(0x681c));
    // wprintf(L"vmwrite(0x6c14, 0x%x);\n", vmread(0x6c14));
    wprintf(L"vmwrite(0x812, 0x%x);\n", vmread(0x812));
    // loop_count[0]=-1;
    // wprintf(L"PAE 0x%x\n", vmread(0x6804)>>5 &1);
    // vmwrite(0x6804, vmread(0x6804)&~(1<<5));
    // wprintf(L"PAE 0x%x\n", vmread(0x6804)>>5 &1);
    // wprintf(L"vmwrite(0x4016, 0x%x);\n", vmread(0x4016));
    if (!__builtin_setjmp(env))
    {
        wprintf(L"Launch a VM\r\r\n");
        asm volatile("cli");
        asm volatile("vmlaunch" ::
                         : "memory");
        goto error_vmx;
    }
    else
        goto disable_vmx;

error_vmx:
    wprintf(L"VMLAUNCH failed: ");
    wprintf(L"Error Number is %d\r\n", vmread(0x4400));
    goto disable_vmx;

error_vmptrld:
    wprintf(L"VMPTRLD failed.\r\n");
    goto disable_vmx;

error_vmclear:
    wprintf(L"VMCLEAR failed.\r\n");
    goto disable_vmx;

error_vmxon:
    wprintf(L"VMXON failed.\r\n");
    goto disable_vmx;

disable_vmx:
    asm volatile("vmxoff");
    asm volatile("mov %%cr4, %0"
                 : "=r"(regs.cr4));
    regs.cr4 &= ~0x2000; // CR4.VME[bit 13] = 0
    asm volatile("mov %0, %%cr4" ::"r"(regs.cr4));
    goto exit;

error_vmx_disabled:
    putws(L"VMX is disabled by the firmware\r\n");
    goto exit;

error_vmx_not_supported:
    putws(L"VMX is not supported in this processor\r\n");
    goto exit;

exit:
    putws(L"Press any key to go back to the UEFI menu\r\n");
    SystemTable->RuntimeServices->ResetSystem(EfiResetShutdown, EFI_SUCCESS, 0, NULL);
    getwchar();
    return EFI_SUCCESS;
}
