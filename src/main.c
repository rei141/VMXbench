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
#include "msr.h"
#include "fuzz.h"
#include "binc.h"
extern EFI_SYSTEM_TABLE *SystemTable;

extern uint64_t vmxonptr;

static int env[28];

uint16_t vmcs_index[] = {0x0000, 0x0002, 0x0004, 
                         0x0800, 0x0802, 0x0804, 0x0806, 0x0808, 0x080a, 0x080c, 0x080e,
                         0x0810, 0x0812, 
                         0x0c00, 0x0c02, 0x0c04, 0x0c06, 0x0c08, 0x0c0a, 0x0c0c, 
                         0x2000, 0x2002, 0x2004, 0x2006, 0x2008, 0x200a, 0x200c, 0x200e, 
                         0x2010, 0x2012, 0x2014, 0x2016, 0x2018, 0x201a, 0x201c, 0x201e, 
                         0x2020, 0x2022, 0x2024, 0x2026, 0x2028, 0x202a, 0x202c, 0x202e,
                         0x2030, 0x2032, 
                         0x2400, 
                         0x2800, 0x2802, 0x2804, 0x2806, 0x2808, 0x280a, 0x280c, 0x280e,
                         0x2810, 0x2812, 0x2814,         0x2818,
                         0x2c00, 0x2c02, 0x2c04, 0x2c06,
                         0x4000, 0x4002, 0x4004, 0x4006, 0x4008, 0x400a, 0x400c, 0x400e, 
                         0x4010, 0x4012, 0x4014, 0x4016, 0x4018, 0x401a, 0x401c, 0x401e, 
                         0x4020, 0x4022, 
                         0x4400, 0x4402, 0x4404, 0x4406, 0x4408, 0x440a, 0x440c, 0x440e, 
                         0x4800, 0x4802, 0x4804, 0x4806, 0x4808, 0x480a, 0x480c, 0x480e, 
                         0x4810, 0x4812, 0x4814, 0x4816, 0x4818, 0x481a, 0x481c, 0x481e, 
                         0x4820, 0x4822, 0x4824, 0x4826, 0x4828, 0x482a,         0x482e, 
                         0x4c00, 
                         0x6000, 0x6002, 0x6004, 0x6006, 0x6008, 0x600a, 0x600c, 0x600e, 
                         0x6400, 0x6404, 0x6402, 0x6408, 0x6406, 0x640a, 
                         0x6800, 0x6802, 0x6804, 0x6806, 0x6808, 0x680a, 0x680c, 0x680e, 
                         0x6810, 0x6812, 0x6814, 0x6816, 0x6818, 0x681a, 0x681c, 0x681e, 
                         0x6820, 0x6822, 0x6824, 0x6826, 0x6828, 0x682a, 0x682c, 
                         0x6c00, 0x6c02, 0x6c04, 0x6c06, 0x6c08, 0x6c0a, 0x6c0c, 0x6c0e, 
                         0x6c10, 0x6c12, 0x6c14, 0x6c16, 0x6c18, 0x6c1a, 0x6c1c};

int vmcs_num;


#define INPUT_READY 8000
#define EXEC_DONE 8001
#define QEMU_READY 8004
#define VMCS_READY 8005

uint16_t l = 54;
uint16_t shiftcount;
uint8_t *input_buf;
struct hv_vp_assist_page *current_vp_assist;

uint64_t restore_vmcs[200];
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
uint64_t index_selector_count;

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

volatile uint64_t *apic_base;


uint64_t get_apic_base() {
    uint32_t edx = 0;
    uint32_t eax = 0;
    asm volatile("rdmsr" : "=a"(eax), "=d"(edx) : "c"(MSR_IA32_APICBASE));
    return ((uint64_t)edx << 32) | eax;
}

void initialize_apic() {
    uint64_t apic_addr = get_apic_base();
    apic_base = (uint64_t *)(apic_addr & 0xFFFFFFFFFFFFF000);
    apic_base[APIC_SVR / 4] = 0xFF | APIC_ENABLE;
    apic_base[APIC_TPR / 4] = 0;
}

void invalidate_vmcs(uint32_t field, uint32_t bits){
    uint64_t value = vmread(field);
    value = value ^ (1 << bits);
    vmwrite(field, value);
}

void host_entry(uint64_t arg)
{
    uint64_t reason = vmread(0x4402);
    uint64_t rip = vmread(0x681E); // Guest RIP
    uint64_t len = vmread(0x440C); // VM-exit instruction length

    wprintf(L"exit reason = %d, rip = 0x%x, len = %d\r\n", reason, rip, len);
    if (reason == 18)
    {
        vmwrite(0x681e, rip + len);
        goto fuzz;
    }
    if (guest_hang == 1)
    {
        if (reason & 0x80000000)
        {
            wprintf(L"guest_hang==1\r\n");
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
        wprintf(L"Error Number is %d\r\n", vmread(0x4400));

        print_exitreason(reason);

        // for (int i = 0; i < vmcs_num; i++)
        // {
        //     if (!(0
        //           // (vmcs_index[i] & 0x0f00) == 0xc00
        //           // || (vmcs_index[i] & 0x0f00) == 0x400
        //           // (vmcs_index[i] & 0x0f00) == 0x400
        //           ))
        //     {
        //         // wprintf(L"vmwrite(0x%x,0x%x);\n", vmcs_index[i], vmread(vmcs_index[i]));
        //         vmwrite(vmcs_index[i], restore_vmcs[i]);
        //     }
        // }
        guest_hang = 1;
        asm volatile("vmresume\n\t");
        __builtin_longjmp(env, 1);
        vmwrite(0x681E, (uint64_t)guest_entry);
        asm volatile("vmresume\n\t");
    }
    guest_hang = 1;
    if (reason == 0x0 || reason == 0x1 || reason == 43 || reason == 48 || reason == 47)
    {
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
        wprintf(L"VM exit reason %d\r\n", reason);
        if (reason == 65)
        {
            __builtin_longjmp(env, 1);
        }
        vmwrite(0x681E, rip + len);
        asm volatile("vmresume\n\t");
    }

    if (reason == 18)
    {
    fuzz:
        guest_hang = 0;

        loop_count++;
        wprintf(L"%d\r\n", loop_count);
        if (loop_count > 65){
            __builtin_longjmp(env, 1);
        }
        if (index_count >= 0x700) {
            __builtin_longjmp(env, 1);
        }
        input_buf[EXEC_DONE] = 1;

        uint16_t is_input_ready = 0;
        uint16_t windex;
        uint64_t wvalue;

        if(loop_count <= 1) {


            int error;
            uint64_t *v = (uint64_t *)0x3fffffffe000;

            uint64_t aa =  0x4000;


        vmwrite(0x2, loop_count);
        // is_input_ready = input_buf[INPUT_READY];
        // while (!is_input_ready)
        // {
        //     is_input_ready = input_buf[INPUT_READY];
        // }
        // input_buf[INPUT_READY] = 0;
        // is_input_ready = input_buf[INPUT_READY];
        // while (!is_input_ready)
        // {
        //     is_input_ready = input_buf[INPUT_READY];
        // }
        // input_buf[INPUT_READY] = 0;

            input_buf[INPUT_READY] = 0;
            wprintf(L"fuzz start\r\n");
            wvalue = get64b(index_count);
            index_count += 8;
            invept_t inv;
            uint64_t eptp = (uint64_t)pml4_table_2;
            uint64_t type = get8b(index_count++) % 4;
            inv.rsvd = 0;
            inv.ptr = eptp|0x5e;
            if (get8b(index_count++) % 2 == 0)
            {
                inv.ptr = eptp;
            }

            invvpid_t inv2;
            inv2.vpid = get16b(index_count++);
            index_count += 2;
            inv2.gva = wvalue;
            inv2.rsvd = 0;
index_count = 0;
            wprintf(L"guest_entry: %x\r\n", (uint64_t)guest_entry);
            int tmp = 0;
            for (int i = 0 * 8; i < vmcs_num * 8; i += 8)
            // for (int i = 0 * 8; i < vmcs_num * 8/2; i += 8)
            {
                if (i / 8 == vmcs_num)
                {
                    break;
                }
                windex = i / 8;
                windex = vmcs_index[windex];
                vmread(windex);
                // wvalue = ((uint64_t *)(input_buf) + i / 8)[0];
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
                    // continue;
                }
                // */
                if (windex < 0x2000)
                { // 16b
                    wvalue = get16b(tmp);
                    tmp += 2;
                }
                else if (windex < 0x4000)
                { // 64b
                    wvalue = get64b(tmp);
                    tmp += 8;
                }
                else if (windex < 0x6000)
                { // 32b
                    wvalue = get32b(tmp);
                    tmp += 4;
                }
                else
                { // 64b
                    wvalue = get64b(tmp);
                    tmp += 8;
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
                    // wvalue = 1;
                    wvalue = wvalue%(BX_ACTIVITY_STATE_MWAIT_IF+1);
                    // wvalue = (wvalue == 1 || wvalue == 3 ? 0 : wvalue);
                }
                if (windex == 0x482e){
                    if((wvalue & 0x3)== 0){
                        wvalue = 0;
                    }
                }
                if (windex == 0x4824)
                {
                    // wvalue = 1;
                    // wvalue &= ~(1<<4);
                    // wvalue |= 1<<31 ;
                    // wvalue &= ~((0x7) <<8);
                    // wvalue |= ((0x2) <<8);
                }

                vmwrite(windex, wvalue);
                // wprintf(L"%d vmwrite(0x%x, 0x%x);\n",i/4, windex, wvalue);
                // vmwrite(0x482e,0xffffffff);
            }

            vmwrite(0x4800, get_seg_limit(vmread(0x800)));
            vmwrite(0x4802, get_seg_limit(vmread(0x802)));
            vmwrite(0x4804, get_seg_limit(vmread(0x804)));
            vmwrite(0x4806, get_seg_limit(vmread(0x806)));
            vmwrite(0x4808, get_seg_limit(vmread(0x808)));
            vmwrite(0x480a, get_seg_limit(vmread(0x80a)));


            // for (int i = 0; i < vmcs_num; i++){
            //     uint64_t v = vmread(vmcs_index[i]);
            //     write64b(0x3000 + i*8, v);
            // }
            index_count = 0x500;
            index_selector_count = 0x700;
        }

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
wprintf(L"helo\r\n");

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

        windex = vmcs_index[get16b(index_count) % vmcs_num]; // at 0x500 byte
        index_count += 2;
        uint32_t bits;
        uint32_t c = get8b(index_selector_count++) % 3;
        
        c = 1;
        wprintf(L"count %d\r\n", c);
        for (int i = 0; i < c; i++){
            bits = get8b(index_count++);
            // index_count++;

            if (windex < 0x2000)
            { // 16b
                bits %= 16;
            }
            else if (windex < 0x4000)
            { // 64b
                bits %= 64;
            }
            else if (windex < 0x6000)
            { // 32b
                bits %= 32;
            }
            else
            { // 64b
                bits %= 64;
            }
            invalidate_vmcs(windex, bits);
            wprintf(L"0x%x #%d\r\n", windex, bits);
            wprintf(L"vmwrite(0x%x, 0x%x);\r\n",windex, vmread(windex));

            // if ((windex & 0x0f00) != 0xc00)
            // {
            //     if (windex == 0x400e || windex == 0x681c || windex == 0x681e || windex == 0x6816 || windex == 0x681E || windex == 0x2800 || windex == 0x2000 || windex == 0x2002 || windex == 0x2004 || windex == 0x2006 || windex == 0x2008 || windex == 0x200a || windex == 0x200c || windex == 0x200e || windex == 0x2012 || windex == 0x2014 || windex == 0x2016 || windex == 0x2024 || windex == 0x2026 || windex == 0x2028 || windex == 0x202a)
            //     {
            //         // vmwrite(windex, 0x3fffffffe000);
            //         wvalue = get64b(index_count);
            //         index_count += 8;
            //         vmwrite(windex, wvalue & ~(0xFFF));
            //     }
            // }
            if(i == c-1)
                continue;
            windex = vmcs_index[get16b(index_count) % vmcs_num]; // at 0x500 byte
            index_count += 2;
        }

        if (current_evmcs)
        {
            /* HOST_RIP */
            current_evmcs->hv_clean_fields &= ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_HOST_GRP1;
            /* HOST_RSP */
            current_evmcs->hv_clean_fields &= ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_HOST_POINTER;
        }
        else
        {
            // vmwrite(0x681E, (uint64_t)guest_entry);
            vmwrite(0x681E, rip + len);
            vmwrite(0x440c, 0);
        }
        // wprintf(L" sizeof(exec_l1_table); %d\n",sizeof(exec_l1_table)/sizeof(uint64_t));
        // c = get8b(index_count++) % 6;
        c = 1;
        wprintf(L" FUZZ L1 !!!\r\n");
        for (int i = 0; i < c; i++){
            int selector = get16b(index_selector_count) % L1_TABLE_SIZE;
            index_selector_count += 2;
            wprintf(L" #%d",selector);
            exec_l1_table[selector]();
        }

        shiftcount = 0;
    // current_evmcs->hv_enlightenments_control.nested_flush_hypercall=1;
    // current_vp_assist->nested_control.features.directhypercall=1;
        // input_buf[0]=0;
        // wprintf(L"  0x%x",(((VMX_MSR_MISC >> 6)&0x7) & 0x1));
        wprintf(L"entry 0x%x\r\n", vmread(0x681e));
        // for (int i = 0; i < vmcs_num; i++)
        // {
        //     wprintf(L"vmwrite(0x%x, 0x%x);\r\n", vmcs_index[i], vmread(vmcs_index[i]));
        // }
        vmwrite(0x2800, 0xffffffffffffffff);
        vmwrite(0x4826, 0x0); // reboot

        asm volatile("vmresume\n\t");
        wprintf(L"VMRESUME failed: \r\n");

        guest_hang = 1;

        if (current_evmcs)
        {
            /* HOST_RIP */
            current_evmcs->hv_clean_fields &= ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_HOST_GRP1;
            /* HOST_RSP */
            current_evmcs->hv_clean_fields &= ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_HOST_POINTER;
            // current_evmcs->revision_id = 1;
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
struct xsave {
    uint8_t legacy_area[512];
    union {
        struct {
            uint64_t xstate_bv;
            uint64_t xcomp_bv;
        };
        uint8_t header_area[64];
    };
    uint8_t extended_area[];
};
_Noreturn void guest_entry(void)
{
    while (1)
    {
        if (loop_count == 0)
        {
            vmcall(1);
        }
        //!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
        uint64_t *v = (uint64_t *)0x3fffffffe001;
        uint64_t aa =  0x4000;

        uint16_t instr_selector;
        for (int i = 0; i < 20; i++)
        {
            int selector = get16b(index_selector_count) % L2_TABLE_SIZE;
            index_selector_count += 2;
            exec_l2_table[selector]();
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
uint64_t *SetupIdentityPageTable(void)
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
int rdrand64_step(unsigned long long *rand) {
    unsigned char ok;
    asm volatile ("rdrand %0; setc %1"
                  : "=r" (*rand), "=qm" (ok));
    return (int) ok;
}
volatile uint64_t *apic_base;

struct hv_enlightened_vmcs *current_evmcs;
// int num_device;
EFI_STATUS
EFIAPI
EfiMain(
    IN EFI_HANDLE ImageHandle,
    IN EFI_SYSTEM_TABLE *_SystemTable)
{
    uint32_t error;
    struct registers regs;
    index_selector_count = 0x700;
    SystemTable = _SystemTable;

    vmcs_num = sizeof(vmcs_index) / sizeof(vmcs_index[0]);
    // struct xsave buf[3];
    //             struct fpu_state_buffer fsb;
    //             asm volatile("xsave (%0)":: "r"(&buf[0]):);
    // unsigned long long seed;
    // rdrand64_step(&seed);
    // init_genrand((unsigned long)seed);
    // init_genrand(1);
    // wprintf(L"rand 0x%x\r\n", genrand_int32());
    // wprintf(L"rand 0x%x\r\n", get64b(0));
    wprintf(L"Starting VMXbench ...\r\n");

    uint8_t ivshm_dev = 0;
    uint8_t dev = 0;
    // ScanAllBus();
    // wprintf(L"device 0x%x\r\n",num_device);
    // for (int i = 0; i < num_device; i++){
    //     // wprintf(L"device %d: 0x%x, 0x%x\r\n",i,devices[i].bus,devices[i].function);
    //     for (dev = 0; dev < 32; dev++)
    //     {
    //         uint16_t vendor_id = ReadVendorId(devices[i].bus, dev, devices[i].function);
    //         if (vendor_id == 0x1af4)
    //         {
    //             ivshm_dev = dev;
    //             wprintf(L"bus:%d, dev:%d, func:%d, vendor : %04x\r\n", devices[i].bus, dev, devices[i].function, vendor_id);
    //             break;
    //         }
    //     }
    //     if(ivshm_dev){
    //         break;
    //     }
    // }
    // uintptr_t bar2 = ReadBar(0, ivshm_dev, 0, 2);
    // wprintf(L"bar2:0x%x\r\n", bar2);
    input_buf = binary_data;
    input_buf[QEMU_READY] = 1;
    input_buf[VMCS_READY] = 0;

    uint32_t ecx, ebx, edx;
    uint32_t eax;
    asm volatile("cpuid"
                 : "=a"(eax), "=c"(ecx), "=b"(ebx), "=d"(edx)
                 : "a"(0x40000080)
                 :);
    wprintf(L" ecx: 0x%x", ecx);
    wprintf(L" ebx: 0x%x", ebx);
    wprintf(L" edx: 0x%x\r\n", edx);
    if (ebx == 0x7263694D && ecx == 0x666F736F && edx == 0x53562074)
    { // Microsoft SV?
        wprintf(L" evmcs enable\r\n");
        uint64_t vp_addr = (uint64_t)vp_assist | 0x1;
        wrmsr(0x40000073, vp_addr);
        current_vp_assist = (void *)vp_assist;
        current_vp_assist->current_nested_vmcs = (uint64_t)vmcs;
        current_vp_assist->enlighten_vmentry = 1;
        current_evmcs = (struct hv_enlightened_vmcs *)vmcs;
    }

    // wprintf(L"%d, dev %d\r\n",(ivshm_dev==dev),ivshm_dev);
    // ivshm_dev++;


    // for(int i = 0; i < 20; i++){
    // wprintf(L"buf[%d] = %x\r\n", i,input_buf[i]);}
    // input_buf[3000] = 0xdead;
    // return 1;
    SetupIdentityPageTable();

    // check the presence of VMX support
    asm volatile("cpuid"
                 : "=c"(ecx)
                 : "a"(1)
                 : "ebx", "edx");
    wprintf(L"cpuid(eax=1): 0x%x\r\n", ecx);

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
    wprintf(L" cr4 0x%x\r\n", regs.cr4);
    regs.cr4 = apply_fixed_bits(regs.cr4, 0x488, 0x489);
    asm volatile("mov %0, %%cr4" ::"r"(regs.cr4));
    wprintf(L" cr4 0x%x\r\n", regs.cr4);

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
    wprintf(L" ia32_efer 0x%x\r\n", regs.ia32_efer);
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
    // wprintf(L" vmwrite(0x6800, 0x%x);\r\n", vmread(0x6800));
    // vmwrite(0x6c00, regs.cr0);
    vmwrite_gh(0x6802, 0x6c02, regs.cr3);
    vmwrite_gh(0x6804, 0x6c04, regs.cr4);
    wprintf(L" cr3 0x%x\r\n", regs.cr3);
    wprintf(L" cr0 pageing 0x%x\r\n", regs.cr0 >> 31);

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
        posted_int_desc[i] = get64b(i);
        index_count += 8;
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

    // exec_page_table();

    uint64_t eptp = (uint64_t)pml4_table;
    uint64_t eptp2 = (uint64_t)pml4_table_2;
    // wprintf(L"eptp 0x%x\r\n", eptp);
    // eptp |= 0x18;
    eptp |= 0x5e; // WB
    // eptp |= 0x58; // UC
    eptp2 |= 0x5e;
    // eptp2 |= 0x58;
    // wprintf(L"eptp 0x%x\r\n", eptp);
    vmwrite(0x201a, eptp);

    eptp_list[0] = eptp;
    eptp_list[1] = eptp2;
    eptp_list[2] = eptp2;
    eptp_list[3] = eptp2;
    eptp_list[4] = eptp2;
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
                    //   1 << 7 |
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
    // wprintf(L"vmwrite(0x2806, 0x%x);\r\n", vmread(0x2806));
    // wprintf(L"guest entry 0x%x\r\n",vmread(0x681e));
    // wprintf(L"vmwrite(0x4000, 0x%x);\r\n",vmread(0x4000));
    // wprintf(L"vmwrite(0x4000, 0x%x);\r\n",apply_allowed_settings(0,0x481));
    // wprintf(L"current evmcs 0x%x\r\n", current_evmcs);
    // uint64_t current_vmcsptr;
    // vmptrst(&current_vmcsptr);
    // wprintf(L"current_vmcsptr 0x%x\r\n", current_vmcsptr);
    // wprintf(L"revision id = 0x%x\r\n",VMXReadRevisionID((bx_phy_address) vmread(VMCS_64BIT_GUEST_LINK_POINTER)));
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
        // wprintf(L"vmwrite(0x%x, 0x%x);\r\n", vmcs_index[i], restore_vmcs[i]);
    }

    if (current_evmcs)
    {
        current_evmcs->hv_clean_fields = 0;
        // current_evmcs->revision_id = 1;
    }
    // input_buf[1000] = 0xdead;
    // wprintf(L"vmwrite(0x4000, 0x%x);\r\n",vmread(0x4000));
    // vmwrite(0x401e,vmread(0x401e)|1<<15);
    // wprintf(L"vmwrite(0x4002, 0x%x);\r\n", vmread(0x4002));
    wprintf(L"vmwrite(0x401e, 0x%x);\r\n", vmread(0x401e));
    // wprintf(L"VMX_MSR_VMX_PROCBASED_CTRLS2_LO 0x%x;\r\n", VMX_MSR_VMX_PROCBASED_CTRLS2_LO);
    // wprintf(L"VMX_MSR_VMX_PROCBASED_CTRLS2_HI 0x%x;\r\n", VMX_MSR_VMX_PROCBASED_CTRLS2_HI);
    // wprintf(L"VMX_VM_EXEC_CTRL3_VMCS_SHADOWING 0x%x;\r\n", vmread(0x401e)&VMX_VM_EXEC_CTRL3_VMCS_SHADOWING);
    
    if (vmread(0x401e) & (1 << 13))
        wprintf(L" vmfunc enable\r\n");
    if (vmread(0x401e) & (1 << 1)){
        wprintf(L" ept enable\r\n");
    }
    else{
        vmwrite(0x201a, 0);
        wprintf(L" ept disable\r\n");
    }
    if (vmread(0x401e) & (1 << 20))
        wprintf(L" xsaves enable\r\n");

    wprintf(L"vmwrite(0x201a, 0x%x);\r\n", vmread(0x201a));

    for (int i = 0; i < vmcs_num; i++){
        wprintf(L"vmwrite(0x%x, 0x%x);\r\n", vmcs_index[i], vmread(vmcs_index[i]));
    }

    vmwrite(0x2800, 0xffffffffffffffff);
    // for (int i = 0; i < vmcs_num; i++)
    // {
    //     restore_vmcs[i] = vmread(vmcs_index[i]);
    //     wprintf(L"0x%x 0x%x\r\n", vmcs_index[i], restore_vmcs[i]);
    // }
    wprintf(L"0x%x 0x%x\r\n", 0x4826, vmread(0x4826));
    vmwrite(0x4826, 0x0); // reboot
    wprintf(L"0x%x 0x%x\r\n", 0x4826, vmread(0x4826));
    // for (int i = 0; i < vmcs_num; i++)
    // {
    //     uint64_t val = vmread(vmcs_index[i]);
    //     if (restore_vmcs[i] != val){
    //         wprintf(L"D 0x%x 0x%x\r\n", vmcs_index[i], val);
    //     }
    // }
    // rdmsr(0x480);
    // __builtin_longjmp(env, 1);
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
    getwchar();
    return EFI_SUCCESS;
}
