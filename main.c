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
// #include <string.h>
// #include <Uefi.h>
// #include <Uefi/UefiSpec.h>
// #include <stddef.h>
#include <stdbool.h>
// #include <Library/UefiLib.h>
// #include <Protocol/PciIo.h>
// #include <Protocol/DriverBinding.h>
// #include <IndustryStandard/Pci.h>
// #include <Protocol/DriverBinding.h>
// #include <Protocol/PciRootBridgeIo.h>
// #include <Protocol/DevicePath.h>
// #include <Library/UefiBootServicesTableLib.h>
// #include <Protocol/PciRootBridgeIo.h>
// #include <IndustryStandard/Pci22.h>
#include "pci.h"
#include "vmx.h"
#include "uefi.h"
extern EFI_SYSTEM_TABLE  *SystemTable;

extern uint64_t vmxonptr;
// #include <Library/ShellLib.h>
// #include <Library/UefiShellDebug1CommandsLib/Pci.h>
/** ***************************************************************************
 * @section section_uefi Section 1. UEFI definitions
 * This section contains several basic UEFI type and function definitions.
 *************************************************************************** */


/** ***************************************************************************
 * @section section_vmx Section 2. VMX definitions
 * This section contains several basic VMX function definitions.
 *************************************************************************** */

static inline uint64_t vmcall_with_vmcall_number(uint64_t vmcall_num)
{
    uint64_t ret;
    asm volatile ("vmcall"
		  : "=a" (ret)
		  : "a" (vmcall_num)
		  : "memory", "rdx", "r8", "r9", "r10", "r11");
    return ret;
}

/** ***************************************************************************
 * @section section_vmxbench Section 3. VMXbench
 * This section contains VMXbench main functions
 *************************************************************************** */

static int env[28];

static uint64_t tsc_exit[10], tsc_entry[10];
uint16_t input_from_file[4096 / sizeof(uint16_t)];

// EFI_STATUS read_input_from_file(EFI_SYSTEM_TABLE *SystemTable) {
//     EFI_STATUS Status;
//     EFI_GUID SimpleFileSystemProtocolGuid = EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID;
//     EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *SimpleFileSystemProtocol;
//     Status = SystemTable->BootServices->LocateProtocol(
//         &SimpleFileSystemProtocolGuid,
//         NULL,
//         (VOID **)&SimpleFileSystemProtocol
//     );
//     if (EFI_ERROR(Status)) {
//         wprintf(L"LocateProtocol %r\n", Status);
//         return Status;
//     }
    
//     EFI_FILE_PROTOCOL *Root;
//     Status = SimpleFileSystemProtocol->OpenVolume(
//         SimpleFileSystemProtocol,
//         &Root
//     );
//     if (EFI_ERROR(Status)) {
//         wprintf(L"OpenVolume %r\n", Status);
//         return Status;
//     }   
    

//     EFI_FILE_PROTOCOL *File;
//     CHAR16 *Path = L"input";
//     Status = Root->Open(
//         Root,
//         &File,
//         Path,
//         EFI_FILE_MODE_READ,
//         EFI_FILE_READ_ONLY
//     );
//     if (EFI_ERROR(Status)) {
//         wprintf(L"Open %r\n", Status);
//         return Status;
//     }
//     wprintf(L"hello\n");
//     UINTN BufferSize = 4096;
//     Status = File->Read(
//         File,
//         &BufferSize,
//         (VOID *)input_from_file
//     );
//     if (EFI_ERROR(Status)) {
//         wprintf(L"Read %r\n", Status);
//         return Status;
//     }

//     wprintf(L"BufferSize = %d\n", BufferSize);

//     return EFI_SUCCESS;
// }

void print_results()
{
    uint64_t exit_min = UINT64_MAX, entry_min = UINT64_MAX, exit_max = 0, entry_max = 0;
    uint64_t exit_avg = 0, entry_avg = 0;

    for (int i = 0; i < 10; i++) {
	wprintf(L"VM exit[%d]: %5d, VM entry[%d]: %5d\r\n", i, tsc_exit[i], i, tsc_entry[i]);
	if (tsc_exit[i] < exit_min) exit_min = tsc_exit[i];
	if (tsc_exit[i] > exit_max) exit_max = tsc_exit[i];
	exit_avg += tsc_exit[i];
	if (tsc_entry[i] < entry_min) entry_min = tsc_entry[i];
	if (tsc_entry[i] > entry_max) entry_max = tsc_entry[i];
	entry_avg += tsc_entry[i];
    }
    wprintf(L"VM exit : min = %5d, max = %5d, avg = %5d\r\n", exit_min, exit_max, exit_avg / 10);
    wprintf(L"VM entry: min = %5d, max = %5d, avg = %5d\r\n", entry_min, entry_max, entry_avg / 10);
}

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

_Noreturn
void guest_entry(void);

uint16_t vmcs_index[] = {0x0000,0x0002,0x0004,0x0800,0x0802,0x0804,0x0806,0x0808,0x080a,0x080c,0x080e,0x0810, \
0x0812,0x0c00,0x0c02,0x0c04,0x0c06,0x0c08,0x0c0a,0x0c0c,0x2000,0x2002,0x2004,0x2006,0x2008,0x200a,0x200c, \
0x200e,0x2010,0x2012,0x2014,0x2016,0x2018,0x201a,0x201c,0x201e,0x2020,0x2022,0x2024,0x2028,0x202a,0x202c, \
0x202e,0x2032,0x2400,0x2800,0x2802,0x2804,0x2806,0x2808,0x280a,0x280c,0x280e,0x2810,0x2c00,0x2c02,0x2c04, \
0x4000,0x4002,0x4004,0x4006,0x4008,0x400a,0x400c,0x400e,0x4010,0x4012,0x4014,0x4016,0x4018,0x401a,0x401c, \
0x401e,0x4020,0x4022,0x4400,0x4402,0x4404,0x4406,0x4408,0x440a,0x440c,0x440e,0x4800,0x4802,0x4804,0x4806,0x4808, \
0x480a,0x480c,0x480e,0x4810,0x4812,0x4814,0x4816,0x4818,0x481a,0x481c,0x481e,0x4820,0x4822,0x4824,0x4826, \
0x4828,0x482a,0x482e,0x4c00,0x6000,0x6002,0x6004,0x6006,0x6008,0x600a,0x600c,0x600e,0x6400,0x6404,0x6402, \
0x6408,0x6406,0x640a,0x6800,0x6802,0x6804,0x6806,0x6808,0x680a,0x680c,0x680e,0x6810,0x6812,0x6814,0x6816, \
0x6818,0x681a,0x681c,0x681e,0x6820,0x6822,0x6824,0x6826,0x6c00,0x6c02,0x6c04,0x6c06,0x6c08,0x6c0a,0x6c0c, \
0x6c0e,0x6c10,0x6c12,0x6c14,0x6c16};
#define vmcs_num 153
uint16_t l = 54;
uint16_t * input_buf;
uint64_t restore_vmcs[vmcs_num];
char vmcs[4096] __attribute__ ((aligned (4096)));
char vmcs_backup[4096] __attribute__ ((aligned (4096)));
char shadow_vmcs[4096] __attribute__ ((aligned (4096)));
char shadow_vmcs2[4096] __attribute__ ((aligned (4096)));
char vmxon_region[4096] __attribute__ ((aligned (4096)));
uint32_t revision_id;
uint32_t host_hang;
uint32_t get_seg_limit(uint32_t selector)
{
	uint32_t limit;
    asm volatile ("lsl %1, %0" : "=r" (limit) : "r" (selector));
	return limit;
}
int32_t get_seg_access_rights(uint32_t selector)
{
	uint32_t access_rights;
	asm volatile ("lar %1, %0" : "=r" (access_rights) : "r" (selector));
	return access_rights >> 8;
}
uint64_t get_seg_base(uint32_t selector) { return 0; }
uint64_t count = 0;
void host_entry(uint64_t arg)
{
    input_buf[4003] = 0;
    // tsc_exit[index] = rdtsc() - arg;
    uint64_t reason = vmread(0x4402);
    if(host_hang == 1){
        if(reason & 0x80000000){
            wprintf(L"host_hang==1\n");        
            __builtin_longjmp(env, 1);
        }
        else{
            // wprintf(L"host_hang==1\n");        
            host_hang = 0;
            reason = 18;
            arg=1;
            vmwrite(0x681E, (uint64_t)guest_entry);
            vmwrite(0x440c, 0);
            goto fuzz;
        }
    }
    // wprintf(L"Start fuzzing...\r\n");
    // wprintf(L"vmexit reason %0d\r\n", reason);
        // wprintf(L"VM exit reason %d\n",reason);        
        uint64_t rip = vmread(0x681E); // Guest RIP
        uint64_t len = vmread(0x440C); // VM-exit instruction length
        wprintf(L"exit reason = %d, rip = 0x%x, len = %d\n", reason,rip,len);
    if (reason & 0x80000000){
        wprintf(L"VM exit reason 0x%x\n",reason);        
        // uint64_t rip = vmread(0x681E); // Guest RIP
        // uint64_t len = vmread(0x440C); // VM-exit instruction length
        // vmwrite(0x681E, rip + len);
        print_exitreason(reason);
        //     int error;
        // uint32_t revision_id = rdmsr(0x480);
        // uint32_t *ptr;
        // // vmxonptr = (uintptr_t)ptr;
        // // ptr[0] = revision_id;
        // // asm volatile ("vmxon %1" : "=@ccbe" (error) : "m" (ptr));
        // // asm volatile ("vmxoff");
        // // asm volatile ("vmxon %1" : "=@ccbe" (error) : "m" (ptr));
        // // initialize VMCS
        wprintf(L"Initialize VMCS\r\n");
        // __builtin_memset(vmcs, 0, 4096);
        // ptr = (uint32_t *)vmcs;
        // asm volatile ("vmclear %1" : "=@ccbe" (error) : "m" (ptr));
        // ptr[0] = revision_id;
        // asm volatile ("vmptrld %1" : "=@ccbe" (error) : "m" (ptr));
        for(int i=0; i < vmcs_num; i++){
            if(!(0
                // (vmcs_index[i] & 0x0f00) == 0xc00
                // || (vmcs_index[i] & 0x0f00) == 0x400
                // (vmcs_index[i] & 0x0f00) == 0x400
            ))
            {
                // wprintf(L"vmwrite(0x%x,0x%x);\n", vmcs_index[i], vmread(vmcs_index[i]));
                vmwrite(vmcs_index[i],restore_vmcs[i]);
            }
        }
        host_hang = 1;
        asm volatile("vmresume\n\t");
        __builtin_longjmp(env, 1);
        vmwrite(0x681E, (uint64_t)guest_entry);
        asm volatile("vmresume\n\t");
        
    }
    if (reason == 0x0 || reason == 0x1|| reason == 62|| reason == 43){
        // uint64_t rip = vmread(0x681E); // Guest RIP
        // uint64_t len = vmread(0x440C); // VM-exit instruction length
        // wprintf(L"exit reason = 0, rip = 0x%x, len = %d\n", rip,len);
        wprintf(L"guest entry = 0x%x\n",(uint64_t)guest_entry);
        vmwrite(0x681E, (uint64_t)guest_entry);
        //     int error;
        // uint32_t revision_id = rdmsr(0x480);
        // uint32_t *ptr;
        // // vmxonptr = (uintptr_t)ptr;
        // // ptr[0] = revision_id;
        // // asm volatile ("vmxon %1" : "=@ccbe" (error) : "m" (ptr));
        // // asm volatile ("vmxoff");
        // // asm volatile ("vmxon %1" : "=@ccbe" (error) : "m" (ptr));
        // // initialize VMCS
        wprintf(L"Initialize VMCS\r\n");
        // __builtin_memset(vmcs, 0, 4096);
        // ptr = (uint32_t *)vmcs;
        // asm volatile ("vmclear %1" : "=@ccbe" (error) : "m" (ptr));
        // ptr[0] = revision_id;
        // asm volatile ("vmptrld %1" : "=@ccbe" (error) : "m" (ptr));
        for(int i=0; i < vmcs_num; i++){
            if(!(
                // (vmcs_index[i] & 0x0f00) == 0xc00
                // || (vmcs_index[i] & 0x0f00) == 0x400
                (vmcs_index[i] & 0x0f00) == 0x400
            )){
                // wprintf(L"vmwrite(0x%x,0x%x);\n", vmcs_index[i], vmread(vmcs_index[i]));
                vmwrite(vmcs_index[i],restore_vmcs[i]);
            }
        }
        reason = 18;
        arg=1;
        vmwrite(0x681E, (uint64_t)guest_entry);
        vmwrite(0x440c, 0);
        goto fuzz;

        asm volatile("vmresume\n\t");
        __builtin_longjmp(env, 1);
        print_exitreason(reason);
    }
    if (reason == 2){
        // uint64_t rip = vmread(0x681E); // Guest RIP
        // uint64_t len = vmread(0x440C); // VM-exit instruction length
        // wprintf(L"exit reason = 2, rip = 0x%x, len = %d\n", rip,len);
        // wprintf(L"guest entry = 0x%x\n",(uint64_t)guest_entry);
        reason = 18;
        arg=1;
        vmwrite(0x681E, (uint64_t)guest_entry);
        vmwrite(0x440c, 0);
        goto fuzz;
        vmwrite(0x681E, (uint64_t)guest_entry);
        __builtin_longjmp(env, 1);
        asm volatile("vmresume\n\t");
    }  
    if (reason == 46){
        // vmwrite(0x482e,0xffffffff);
        // uint64_t rip = vmread(0x681E); // Guest RIP
        // uint64_t len = vmread(0x440C); // VM-exit instruction length
        // wprintf(L"exit reason = %d, rip = 0x%x, len = %d\n", reason,rip,len);
        vmwrite(0x681E, rip+len);
        asm volatile("vmresume\n\t");
        __builtin_longjmp(env, 1);
    }
    if (reason == 54 || reason == 39|| reason == 40 || reason == 36
        || reason ==50 || reason==16 || reason == 11 || reason ==57
        || reason == 61 || reason == 15 || reason == 13 || reason == 58
        || reason == 12 || reason == 14 || reason ==53 || reason ==51
        || reason == 31 || reason == 32|| reason == 30){
        // uint64_t rip = vmread(0x681E); // Guest RIP
        // uint64_t len = vmread(0x440C); // VM-exit instruction length
        // wprintf(L"exit reason = %d, rip = 0x%x, len = %d\n", reason,rip,len);
        // wprintf(L"guest entry = 0x%x\n",(uint64_t)guest_entry);
        vmwrite(0x681E, rip+len);
        asm volatile("vmresume\n\t");
        __builtin_longjmp(env, 1);
    }
    if(reason == 10){
        // uint64_t rip = vmread(0x681E); // Guest RIP
        // uint64_t len = vmread(0x440C); // VM-exit instruction length
        // wprintf(L"exit reason = %d, rip = 0x%x, len = %d\n", reason,rip,len);      
        vmwrite(0x681E, rip+len);
        asm volatile("vmresume\n\t");
        __builtin_longjmp(env, 1);

    }
    if(reason == 7 || reason == 8 || reason == 24 || reason == 28 || reason == 29 || reason == 37|| reason == 52){   
        reason = 18;
        arg=1;
        vmwrite(0x681E, (uint64_t)guest_entry);
        vmwrite(0x440c, 0);
        goto fuzz;

    }
    // if(reason ==30 ){
    //     wprintf(L"VM exit reason %d\n",reason);        

    //     vmwrite(0x681E, rip+len);
    //     // vmwrite(0x681E, (uint64_t)guest_entry);
    //     asm volatile("vmresume\n\t");
    //     __builtin_longjmp(env, 1);
    // }
    if(reason != 18){
        wprintf(L"VM exit reason %d\n",reason);        
        // wprintf(L"vmwrite(0x6820,0x%0x); // rflags\n",vmread(0x6820));
        // wprintf(L"vmwrite(0x4016, 0x%x); //VMENTRY_INTERRUPTION_INFO\n", vmread(0x4016));
        // wprintf(L"vmwrite(0x4018, 0x%x); //VMENTRY_EXCEPTION_ERR_CODE\n", vmread(0x4018));
        // wprintf(L"vmwrite(0x401a, 0x%x); //VMENTRY_INSTRUCTION_LENGTH\n", vmread(0x401a));
        // wprintf(L"vmwrite(0x4000,0x%x); //pin based ctrl\r\n",vmread(0x4000));
        // wprintf(L"vmwrite(0x4002,0x%x); //cpu based ctrl\r\n",vmread(0x4002));
        // wprintf(L"vmwrite(0x400c,0x%x); //vmexit ctrl\r\n",vmread(0x400c));
        // wprintf(L"vmwrite(0x4012,0x%x); //vmentry ctrl\r\n",vmread(0x4012));
        // wprintf(L"vmwrite(0x401e,0x%x); //secondary ctrl\r\n",vmread(0x401e));
        // for (int i = 0; i < 152;i++){
        //     wprintf(L"vmwrite(0x%x, 0x%x);\r\n", vmcs_index[i], vmread(vmcs_index[i]));
        // }
        if(reason == 65){
        __builtin_longjmp(env, 1);

        }
        // wprintf(L"guest entry = 0x%x\n",(uint64_t)guest_entry);
        vmwrite(0x681E, rip+len);
        // vmwrite(0x681E, (uint64_t)guest_entry);
        asm volatile("vmresume\n\t");
        __builtin_longjmp(env, 1);
    }

    if (reason == 18) {
fuzz:
        // if (count == 0){
        //     input_buf[4001] = 0;
        // }
        // else{
        //     input_buf[4001] = 1;
        // }
	if (arg == 0) {
        // vmcall_with_vmcall_number(13);
        // print_exitreason(reason);
        wprintf(L"goodbye:)\n");
        __builtin_longjmp(env, 1);
	}
            uint16_t flag=0;
        uint16_t windex;
        uint64_t wvalue;

        // uint16_t index;
        // uint32_t *ptr;
        // uint32_t error;
    if (arg == 1) {
        while(1){
            count++;
            wprintf(L"%d\r\n",count);
            // vmcall_with_vmcall_number(13);
            input_buf[4001] = 1; 
            flag++;
            vmwrite(0x2,count);
            flag = input_buf[4000];
            while(1){
                flag = input_buf[4000];
                // wprintf(L"%d",flag);
                // SystemTable->BootServices->Stall(0);
                if(flag != 0){
                    break;
                }
            }
            input_buf[4000] = 0;
            input_buf[4003] = 1;

            wvalue = (uint64_t)input_buf[3]<<48 
            | (uint64_t)input_buf[3] << 32 
            | (uint64_t)input_buf[2] << 16
            | (uint64_t)input_buf[1]; 
            invept_t inv;
            inv.rsvd = 0;
            inv.ptr = wvalue;
            // i.ptr = wvalue;
            invept((uint64_t)(input_buf[0]%2 + 1),&inv);
            inv.rsvd = wvalue;
            inv.ptr = 0;
            inv.ptr = (uint64_t)input_buf[1];
            invvpid((uint64_t)(input_buf[0]%4),&inv);

            // for (int i = 0; i < 4092/sizeof(uint16_t); i += 4) {
            for (int i = 0*4; i <vmcs_num*4; i += 4) {
            // for (int i = 0*4; i <0; i += 4) {
            // for (int i = 4*72; i <4*73; i += 4) {
            // for (int i = 4*60; i <4*71; i += 4) {
            // for (int i = 50*4; i <70*4; i += 4) {
                if(i/4 == vmcs_num) {
                    break;
                }
                windex = i/4;
                windex = vmcs_index[windex];
                vmread(windex);
                wvalue = (uint64_t)input_buf[i];
                if (
                    /* VMCS 16-bit guest-state fields 0x80x */
                    // (windex & 0xfff0) == 0x800 || 
                    // (windex >= 0x810 && windex < 0xC00) 
                    // (windex >= 0x812 && windex < 0xC00) 
                    // (windex >= 0x810 && windex < 0xC00) 
                    // (windex > 0x810 && windex < 0xC00) || 

                    /* VMCS 64-bit control fields 0x20xx */
                    (windex & 0xff00) == 0x2000 
                    // || (windex & 0xff00) == 0x2000 
                    /* VMCS 64-bit guest state fields 0x28xx */
                    // (windex & 0xff00) == 0x2800 ||
                    // || (windex >= 0x2800 && windex < 0x2806) 
                    || windex == 0x2800 
                    || windex == 0x2802 // 0x800000021
                    // || windex == 0x2804 // PAT
                    // || windex == 0x2806 // EFER
                    || windex == 0x2808 // IA32_PERF_GLOBAL_CTRL
                    || (windex >= 0x280a && windex < 0x2C00)  
                    /* VMCS natural width guest state fields 0x68xx */
                    // || (windex & 0xff00) == 0x6800 
                    || windex == 0x6802

                    || windex == 0x6806  // VMCS_GUEST_ES_BASE  
                    || windex == 0x6808  // VMCS_GUEST_CS_BASE  
                    || windex == 0x680a  // VMCS_GUEST_SS_BASE  
                    || windex == 0x680c  // VMCS_GUEST_DS_BASE  
                    || windex == 0x680e  // VMCS_GUEST_FS_BASE  
                    || windex == 0x6810  // VMCS_GUEST_GS_BASE  
                    || windex == 0x6812  // VMCS_GUEST_LDTR_BASE
                    || windex == 0x6814  // VMCS_GUEST_TR_BASE  
                    || windex == 0x6816  // VMCS_GUEST_GDTR_BASE
                    || windex == 0x6818  // VMCS_GUEST_IDTR_BASE
                    // || windex == 0x681a  // VMCS_GUEST_DR7
                    || windex == 0x681c  // VMCS_GUEST_RSP
                    || windex == 0x681e  // VMCS_GUEST_RIP
                    || windex == 0x6820  // VMCS_GUEST_RFLAGS
                    || windex == 0x6822  // VMCS_GUEST_PENDING_DBG_EXCEPTIONS 0x800000021
                    || windex == 0x6824  // VMCS_GUEST_IA32_SYSENTER_ESP_MSR 
                    || windex == 0x6826  // VMCS_GUEST_IA32_SYSENTER_EIP_MSR 
                    || windex == 0x6828  // VMCS_GUEST_IA32_S_CET 
                    || windex == 0x682a  // VMCS_GUEST_SSP  
                    || windex == 0x682c  // VMCS_GUEST_INTERRUPT_SSP_TABLE_ADDR 


                    /* VMCS host state fields */
                    || (windex & 0xfff0) == 0xc00 /* VMCS 16-bit host-state fields 0xc0x */
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
                || windex == 0x4016 //VMENTRY_INTERRUPTION_INFO sometimes hang
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

                //RO fields
                // ||(windex & 0xff00) == 0x2400
                // ||(windex & 0xff00) == 0x4400
                // ||(windex & 0xff00) == 0x6400
                // || windex ==0x400a
                ){         
                    continue;
                }
                // */
                if (windex < 0x2000) {
                } else if (windex < 0x4000) {
                    wvalue = (uint64_t)input_buf[i+3]<<48 | (uint64_t)input_buf[i+2] << 32 | (uint64_t)input_buf[i+1] << 16|wvalue; 
                } else if (windex < 0x6000) {
                    wvalue = (uint32_t)input_buf[i+1]<<16 | wvalue;
                } else {
                    wvalue = (uint64_t)input_buf[i+3]<<48 | (uint64_t)input_buf[i+2] << 32 | (uint64_t)input_buf[i+1] << 16|wvalue; 
                }
                    if(windex == 0x4002){
                        // continue;
                        // wvalue &= ~(1<<22);
                        // wvalue |= (1<<27);
                        wvalue &= ~(1<<27); // sometimes hang
                    }                    
                    if(windex == 0x4000){
                        // continue;
                        // wvalue &= ~(1);
                        // wvalue &= ~(1<<3);
                        
                    }
                    if(windex == 0x401e){
                        // wvalue &= ~(1<<1);
                        // wvalue |= (1<<7);
                        // wvalue &= ~(1<<7);
                        // wvalue &= ~(1<<15);
                        // wvalue &= ~(1<<17);
                        // wvalue &= ~(1<<18);
                        // wvalue &= ~(1<<19);
                        // wprintf(L"wvalue 0x%x\n", wvalue);
                    }
                    if(windex == 0x4012) {
                        // wvalue &= 0xf3ff;
                        wvalue |= 1<<9; // sometimes 0x800000021
                    }                    
                    if(windex == 0x400e || windex == 0x4010 || windex == 0x4014) {
                        wvalue &= 0x1ff;
                    }
                    if(windex == 0x4816){ // CS access rights 9,11,13,15
                        // wvalue |= 0b1001;
                        
                        // wvalue |= (1<<4);
                        // wvalue |= 1<<7;
                        // wvalue &= ~(1<<14);
                        // wvalue |= 1<<13;
                    }
                    if (windex == 0x4814 
                     || windex == 0x481a 
                     || windex == 0x481c 
                     || windex == 0x481e
                     ){
                        // wvalue |= (1<<4 | 1<<15|1<<0);
                        // wvalue |= (1<<4);
                        // wvalue |= (1<<4 | 1<<15);
                        // wvalue |= (1<<1);
                        // wvalue &= ~(1<<16);
                        // wvalue &= ~(1<<16);
                    }
                    if(windex == 0x4818){ // SS access rights
                        // wvalue |= (1<<4);
                    }
                    if(windex == 0x4820){ // SS access rights
                        // wvalue &= ~(1<<4);
                    }
                    if(windex == 0x4822){ // SS access rights
                        wvalue &= ~0xf;
                        wvalue |= 0xb;
                        // wvalue &= ~(1<<4);
                        // wvalue &= ~(1<<16);
                    }
                    if(windex == 0x4826) {
                        // wvalue = 0;
                    }
                    if(windex == 0x4824) {
                        // wvalue &= ~(1<<4);
                        // wvalue |= 1<<31 ;
                        // wvalue &= ~((0x7) <<8);
                        // wvalue |= ((0x2) <<8);
                    }
                    
                    vmwrite(windex, wvalue);
                    // wprintf(L"vmwrite(0x%x, 0x%x);\n",windex, wvalue);
                    // vmwrite(0x482e,0xffffffff);
                }
    
            // input_buf[4001] = 1;

    // vmwrite(0x482e,100000000ull);
    // wprintf(L"vmwrite(0x4016, 0x%x);\n", vmread(0x4016));
// vmwrite(0x4016, 0x80000311);
// vmwrite(0x4016, 0x80000a02);
// vmwrite(0x4016, 0x0);
// vmwrite(0x4016, 0x800004a1);
// vmwrite(0x4016, 0x3539f451);
// vmwrite(0x4016, 0x800006ac);
// vmwrite(0x4016, 0x8000006f);
    // vmwrite(0x4010,513);
    wprintf(L"vmwrite(0x4016, 0x%x);\n", vmread(0x4016));
    wprintf(L"11:0x%x, 10-8:0x%x, 7-0:0x%x\n", (vmread(0x4016)>>11)&1, (vmread(0x4016)>>8)&0x7, vmread(0x4016)&0xff);

    vmwrite(0x4800,get_seg_limit(vmread(0x800)));
    vmwrite(0x4802,get_seg_limit(vmread(0x802)));
    vmwrite(0x4804,get_seg_limit(vmread(0x804)));
    vmwrite(0x4806,get_seg_limit(vmread(0x806)));
    vmwrite(0x4808,get_seg_limit(vmread(0x808)));
    vmwrite(0x480a,get_seg_limit(vmread(0x80a)));
    // vmwrite(vmread(VMCS_64BIT_GUEST_LINK_POINTER))
    VMXWriteRevisionID(vmread(VMCS_64BIT_GUEST_LINK_POINTER), revision_id);

    enum VMX_error_code is_vmentry_error = VMenterLoadCheckVmControls();
    if (! is_vmentry_error){
        wprintf(L"VMX CONTROLS OK!\r\n");
    }else{
        wprintf(L"VMX CONTROLS ERROR %0d\r\n", is_vmentry_error);
    }
    is_vmentry_error = VMenterLoadCheckHostState();
    if (! is_vmentry_error){
        wprintf(L"HOST STATE OK!\r\n");
    }else{
        wprintf(L"HOST STATE ERROR %0d\r\n", is_vmentry_error);
    }
    uint64_t qualification;
    uint32_t is_error = VMenterLoadCheckGuestState(&qualification);
    if (! is_error){
        wprintf(L"GUEST STATE OK!\r\n");
    }else{
        wprintf(L"GUEST STATE ERROR %0d\r\n", qualification);
        wprintf(L"GUEST STATE ERROR %0d\r\n", is_error);
    }
            break;
        }
    }
//     if (count == 2)
// vmwrite(0x4000, 0x1);
    wprintf(L"vmwrite(0x4016, 0x%x);\n", vmread(0x4016));
    wprintf(L"11:0x%x, 10-8:0x%x, 7-0:0x%x\n", (vmread(0x4016)>>11)&1, (vmread(0x4016)>>8)&0x7, vmread(0x4016)&0xff);
    
    // wprintf(L"vmwrite(0x401e, 0x%x);\n", vmread(0x401e));
        for(int i=0; i < vmcs_num; i++){
            if(!(
                (vmcs_index[i] & 0x0f00) == 0xc00
                || (vmcs_index[i] & 0x0f00) == 0x400
                // (vmcs_index[i] & 0x0f00) == 0x400
            )){
                ;
                // wprintf(L"vmwrite(0x%x,0x%x);\n", vmcs_index[i], vmread(vmcs_index[i]));
                // vmwrite(vmcs_index[i],restore_vmcs[i]);
            }
        }

    // uint64_t rip = vmread(0x681E); // Guest RIP
    // uint64_t len = vmread(0x440C); // VM-exit instruction length
    // wprintf(L"rip %x, len %d\n\r", rip , len);

    // vmwrite(0x681E, rip + len);

    windex = vmcs_index[input_buf[152*4]%153];
    wvalue = input_buf[152*4+1]; 
    if(input_buf[152*4+5] &0x1){
        if (windex < 0x2000) {
        } else if (windex < 0x4000) {
            wvalue = (uint64_t)vmread(windex)^(1<<(input_buf[152*4+2]%64)); 
        } else if (windex < 0x6000) {
            wvalue = (uint64_t)vmread(windex)^(1<<(input_buf[152*4+2]%32)); 
        } else {
            wvalue = (uint64_t)vmread(windex)^(1<<(input_buf[152*4+2]%64)); 
        }
    }
    else{
        if (windex < 0x2000) {
        } else if (windex < 0x4000) {
            wvalue = (uint64_t)input_buf[152*4+4]<<48 | (uint64_t)input_buf[152*4+3] << 32 | (uint64_t)input_buf[152*4+2] << 16|wvalue; 
        } else if (windex < 0x6000) {
            wvalue = (uint32_t)input_buf[152*4+2]<<16 | wvalue;
        } else {
            wvalue = (uint64_t)input_buf[152*4+4]<<48 | (uint64_t)input_buf[152*4+3] << 32 | (uint64_t)input_buf[152*4+2] << 16|wvalue;  
        }
    }
    if((windex&0x0f00) != 0xc00){
        if(windex == 0x400e || windex == 0x681c || windex == 0x6816){
            ;
        }
        else{
            vmwrite(windex, wvalue);
            wprintf(L"vmwrite(0x%x,0x%x);\n",windex,wvalue);
        }
    }
    // wprintf(L"vmwrite(0x440e, 0x%x);\n", vmread(0x440e));
    //     vmwrite(0x440e,0x00ffffffffffffff);
    // wprintf(L"vmwrite(0x440e, 0x%x);\n", vmread(0x440e));
    // vmwrite(0x4010,25000);
        vmwrite(0x681E, (uint64_t)guest_entry);
        vmwrite(0x440c, 0);
        // vmwrite(0x4012, vmread(0x4012)&~(1<<15));
    asm volatile("vmresume\n\t");
            // __builtin_longjmp(env, 1);
    host_hang=1;
        for(int i=0; i < vmcs_num; i++){
            // if(!(
            //     // (vmcs_index[i] & 0x0f00) == 0xc00
            //     // || (vmcs_index[i] & 0x0f00) == 0x400
            //     (vmcs_index[i] & 0x0f00) == 0x400
            // ))
            {
                // wprintf(L"vmwrite(0x%x,0x%x);\n", vmcs_index[i], vmread(vmcs_index[i]));
                vmwrite(vmcs_index[i],restore_vmcs[i]);
            }
        }
    // wprintf(L"vmwrite(0x4016, 0x%x);\n", vmread(0x4016));
        // for(int i=0; i < vmcs_num; i++){
        //     // if(!(
        //     //     // (vmcs_index[i] & 0x0f00) == 0xc00
        //     //     // || (vmcs_index[i] & 0x0f00) == 0x400
        //     //     (vmcs_index[i] & 0x0f00) == 0x400
        //     // ))
        //     if(restore_vmcs[i] != vmread(vmcs_index[i]))
        //     {
        //         wprintf(L"index 0x%x, restore_vmcs 0x%x, vmread 0x%x;\n", vmcs_index[i], restore_vmcs[i],vmread(vmcs_index[i]));
        //         // vmwrite(vmcs_index[i],restore_vmcs[i]);
        //     }
        // }
    wprintf(L"VMRESUME failed: \r\n");
            // __builtin_longjmp(env, 1);
    
    asm volatile("vmresume\n\t");
    wprintf(L"VMRESUME failed: \r\n");
    // wprintf(L"0x4000: 0x%x\r\n0x4002: 0x%x\r\n0x401e: 0x%x\r\n",vmread(0x4000),vmread(0x4002),vmread(0x401e));
    // wprintf(L"%x %d\r\n", windex, l);

    wprintf(L"Error Number is %d\r\n", vmread(0x4400));
        for(int i=0; i < vmcs_num; i++){
            if(!(
                // (vmcs_index[i] & 0x0f00) == 0xc00
                // || (vmcs_index[i] & 0x0f00) == 0x400
                (vmcs_index[i] & 0x0f00) == 0x400
            )){
                wprintf(L"vmwrite(0x%x,0x%x);\n", vmcs_index[i], vmread(vmcs_index[i]));
                // vmwrite(vmcs_index[i],restore_vmcs[i]);
            }
        }
    __builtin_longjmp(env, 1);
    // return;

    } 
    // else if (reason == 30) {
    // uint64_t rip = vmread(0x681E); // Guest RIP
    // uint64_t len = vmread(0x440C); // VM-exit instruction length
    // vmwrite(0x681E, rip + len);
	// // print_exitreason(reason);
    // asm volatile("vmresume\n\t");    
    // }else {
    // uint64_t rip = vmread(0x681E); // Guest RIP
    // uint64_t len = vmread(0x440C); // VM-exit instruction length
    // vmwrite(0x681E, rip + len);
    // // wprintf(L"rip : %x\n", rip);
    // // wprintf(L"length : %d\n", len);
    // // wprintf(L"next rip : %x,%x\n", rip+ len,vmread(0x681e));
    // // __builtin_longjmp(env, 1);
    // asm volatile("vmresume\n\t");
	// print_exitreason(reason);
    // __builtin_longjmp(env, 1);
    // wprintf(L"VMRESUME failed: \r\n");
    // }
}

void __host_entry(void);
void _host_entry(void)
{

    asm volatile (
	"__host_entry:\n\t"
	"call host_entry\n\t"
	"vmresume\n\t"
	"loop: jmp loop\n\t"
	);
}
static inline void __invpcid(unsigned long pcid, unsigned long addr,
			     unsigned long type)
{
	struct { uint64_t d[2]; } desc = { { pcid, addr } };
	/*
	 * The memory clobber is because the whole point is to invalidate
	 * stale TLB entries and, especially if we're flushing global
	 * mappings, we don't want the compiler to reorder any subsequent
	 * memory accesses before the TLB flush.
	 *
	 * The hex opcode is invpcid (%ecx), %eax in 32-bit mode and
	 * invpcid (%rcx), %rax in long mode.
	 */
	asm volatile (".byte 0x66, 0x0f, 0x38, 0x82, 0x01"
		      : : "m" (desc), "a" (type), "c" (&desc) : "memory");
}

_Noreturn
void guest_entry(void)
{
    // while(1){
        // vmcall(1);
        // input_buf[4001] = 1;
    // }
    //     rdmsr(0x10);
    // wrmsr(0x10, 0x10);
    while(1){
        // SystemTable->BootServices->Stall(10);
        // asm volatile ("getsec":::); // 11 vmexit x o sometimes hang
        // vmread(0x00);
        // vmwrite(0x00,0);
        if (count ==0)
            vmcall(1);
        // input_buf[4001] = 1;
        // uint64_t zero = 0;
        // void register_state=0;
        asm volatile ("invd":::); //13
        asm volatile ("rdtsc"); // 16
        asm volatile ("mwait"); // 36
        asm volatile ("monitor"); //39
        asm volatile ("pause"); // 40
        asm volatile ("wbnoinvd":::); //54
        asm volatile ("wbinvd":::); //54
        uint64_t zero = 0;
        asm volatile ("rdrand %0" : "+c" (zero) : : "%rax"); // 57
        asm volatile ("rdseed %0" : "+c" (zero) : : "%rax"); // 61
        asm volatile ("invlpg %0" : :"m"(zero)); // 14 vmexit o
        uint32_t ecx;

        asm volatile ("cpuid" : "=c" (ecx) : "a" (1) : "ebx", "edx");

        uint16_t a = input_buf[613]%22;

        uint32_t index;
        uint64_t value;
        int tmp;
        if (a == 1){
        // for (int i = 0; i < 4092/sizeof(uint16_t); i += 6) {
        // for (int i = 0; i < 4092/sizeof(uint16_t); i += 6) {
            if(input_buf[614]%2 == 0){
                index = (uint64_t)input_buf[615];
            // }else{
                index = (uint64_t)0xc000<<16 | (uint64_t)input_buf[615];
            }
            value = (uint64_t)input_buf[619]<<48 |(uint64_t)input_buf[618]<<32 |(uint64_t)input_buf[617]<<16 | (uint64_t)input_buf[616];
            // index = 0xc0000102;
            tmp = rdmsr(index);
            tmp++;
            wrmsr(index,value);
            // uint32_t ecx;
            // asm volatile ("cpuid" : "=c" (ecx) : "a" (index) : "ebx", "edx");
        }
        if(a==21){
            asm volatile ("vmfunc":::);
        }
        if(a==0){
            asm volatile ("mov %0, %%dx" ::"r" (input_buf[620]));
            asm volatile ("mov %0, %%eax" ::"r" ((uint32_t)input_buf[621]));
            asm volatile ("out %eax, %dx");
            asm volatile("mov %0, %%dx" ::"r"(input_buf[622]));
            asm volatile("in %dx, %eax");
        }
        // **********************************
        if(a==2)
        asm volatile ("getsec":::); // 11 vmexit x vmexit vmx non-root
        if(a==3){
                        invept_t inv;
            inv.rsvd = 0;
            inv.ptr = 0;
            // i.ptr = wvalue;
            invept((uint64_t)0,&inv);
            invvpid((uint64_t)0,&inv);
        }
//         // if(a==3) xxx 
//         // asm volatile ("hlt"); //12 x
        if(a==4)
        asm volatile ("invlpg %0" : :"m"(zero)); // 14 vmexit o
        if(a==5)
        asm volatile ("rdpmc": "+c" (zero) : : "%rax"); // 15 vmexit o sometimes hang
        if(a==6)
        asm volatile ("rsm":::); //17 0x80000021x sometimes hang
        if(a==7)
        asm volatile ("rdtscp"); // 51 vmexit sometimes hang
        if(a==8)
        __invpcid(0, 0, 0); // 58 vmexit sometimes hang
        // ;
        if(a==9)
        asm volatile ("xsetbv":::); //55 sometimes hang
        if(a==10)
        asm volatile ("encls":::); // 60 vmexit sometimes hang
        if(a==11)
        asm volatile ("pconfig"); // 65 vmexit sometimes hang
        

        if(a==13)
        asm volatile ("movq %0, %%cr0" : "+c" (zero) : : "%rax");

        // wprintf(L"mov to cr3\r\n");
        // zero = 0x0;
        if(a==14)
        asm volatile ("movq %0, %%cr3" : "+c" (zero) : : "%rax");

        // wprintf(L"mov to cr4\r\n");
        // zero = 0x0;
        if(a==15)
        asm volatile ("movq %0, %%cr4" : "+c" (zero) : : "%rax");

        // wprintf(L"mov to cr8\r\n");
        // zero = 0x0;
        asm volatile ("movq %0, %%cr8" : "+c" (zero) : : "%rax");

        // // wprintf(L"clts\r\n");
        if(a==16)
        asm volatile ("clts"); // sometimes hang

        // // wprintf(L"mov from cr3\r\n");
        uint64_t dummy;

        if(a==17)
        asm volatile ("movq %%cr3, %0" : "=c" (dummy) : : "%rbx");

        // // wprintf(L"mov from cr8\r\n");
        if(a==18)
        asm volatile ("movq %%cr8, %0" : "=c" (dummy) : : "%rbx", "%rsi");

        if(a==19)
{
        asm volatile ("movq %0, %%dr0" : "+c" (zero) : : "%rax");
        asm volatile ("movq %0, %%dr1" : "+c" (zero) : : "%rax");
        asm volatile ("movq %0, %%dr2" : "+c" (zero) : : "%rax");
        asm volatile ("movq %0, %%dr3" : "+c" (zero) : : "%rax");
        asm volatile ("movq %0, %%dr4" : "+c" (zero) : : "%rax");
        asm volatile ("movq %0, %%dr5" : "+c" (zero) : : "%rax");
        asm volatile ("movq %0, %%dr6" : "+c" (zero) : : "%rax");
        asm volatile ("movq %0, %%dr7" : "+c" (zero) : : "%rax");
}
        if(a==20)
{
        asm volatile ("movq %%dr0, %0" : "=c" (dummy) : : "%rbx");
        asm volatile ("movq %%dr1, %0" : "=c" (dummy) : : "%rbx");
        asm volatile ("movq %%dr2, %0" : "=c" (dummy) : : "%rbx");
        asm volatile ("movq %%dr3, %0" : "=c" (dummy) : : "%rbx");
        asm volatile ("movq %%dr4, %0" : "=c" (dummy) : : "%rbx");
        asm volatile ("movq %%dr5, %0" : "=c" (dummy) : : "%rbx");
        asm volatile ("movq %%dr6, %0" : "=c" (dummy) : : "%rbx");
        asm volatile ("movq %%dr7, %0" : "=c" (dummy) : : "%rbx");
}

        // tmp++;
        // wprintf(L"%x\r\n",tmp);
        // wprintf(L"mov to cr0\r\r\n");
            vmcall(1);
    }

    // for(int i = 0; i < 200; i++){
	    // vmcall(1);
        // l++;
    // }
    // __builtin_longjmp(env, 1);
    // wprintf(L"returned\n\r");
    vmcall(0);
    while(1);
}

struct registers {
    uint16_t cs, ds, es, fs, gs, ss, tr, ldt;
    uint32_t rflags;
    uint64_t cr0, cr3, cr4;
    uint64_t ia32_efer, ia32_feature_control;
    struct {
	uint16_t limit;
	uint64_t base;
    } __attribute__((packed)) gdt, idt;
    // attribute "packed" requires -mno-ms-bitfields
};

void save_registers(struct registers *regs)
{
    asm volatile ("mov %%cr0, %0" : "=r" (regs->cr0));
    asm volatile ("mov %%cr3, %0" : "=r" (regs->cr3));
    asm volatile ("mov %%cr4, %0" : "=r" (regs->cr4));
    regs->ia32_efer = rdmsr(0xC0000080);
    asm volatile ("pushf; pop %%rax" : "=a" (regs->rflags));
    asm volatile ("mov %%cs, %0" : "=m" (regs->cs));
}

void print_registers(struct registers *regs)
{
    wprintf(L"CR0: %016x, CR3: %016x, CR4: %016x\r\n", regs->cr0, regs->cr3, regs->cr4);
    wprintf(L"RFLAGS: %016x\r\n", regs->rflags);
    wprintf(L"CS: %04x\r\n", regs->cs);
    wprintf(L"IA32_EFER: %016x\r\n", regs->ia32_efer);
    wprintf(L"IA32_FEATURE_CONTROL: %016x\r\n", rdmsr(0x3a));
}

char host_stack[4096] __attribute__ ((aligned (4096)));
char guest_stack[4096] __attribute__ ((aligned (4096)));
char tss[4096] __attribute__ ((aligned (4096)));
char io_bitmap[4096] __attribute__ ((aligned (4096)));
// char msr_bitmap[4096] __attribute__ ((aligned (4096)));
char msr_bitmap[4096] __attribute__ ((aligned (4096)));
char vmread_bitmap[4096] __attribute__ ((aligned (4096)));
char vmwrite_bitmap[4096] __attribute__ ((aligned (4096)));
char apic_access[4096] __attribute__ ((aligned (4096)));
char virtual_apic[4096] __attribute__ ((aligned (4096)));
// char msr_load[8192] __attribute__ ((aligned (4096)));
// char msr_store[8192] __attribute__ ((aligned (4096)));
// char vmentry_msr_load[8192] __attribute__ ((aligned (4096)));
uint64_t msr_load[1024] __attribute__ ((aligned (4096)));
uint64_t msr_store[1024] __attribute__ ((aligned (4096)));
uint64_t vmentry_msr_load[1024] __attribute__ ((aligned (4096)));
uint64_t posted_int_desc[64] __attribute__ ((aligned (4096)));

struct MSR_BITMAP
{
uint64_t MSR_READ_LO[128];
uint64_t MSR_READ_HI[128];
uint64_t MSR_WRITE_LO[128];
uint64_t MSR_WRITE_HI[128];
} __attribute__ (( aligned (4096) ));

void *
memset (void *dest, int val, int len)
{
  unsigned char *ptr = dest;
  while (len-- > 0)
    *ptr++ = val;
  return dest;
}
  const uint64_t kPageSize4K = 4096;
  const uint64_t kPageSize2M = 512 * kPageSize4K;
  const uint64_t kPageSize1G = 512 * kPageSize2M;

  uint64_t pml4_table[512] __attribute__ ((aligned (4096)));;
  uint64_t pdp_table[512] __attribute__ ((aligned (4096)));;
  uint64_t page_directory[512][512] __attribute__ ((aligned (4096)));;

// }
uint64_t * SetupIdentityPageTable() {
  pml4_table[0] = (uint64_t)&pdp_table[0] | 0x407;
  for (int i_pdpt = 0; i_pdpt < 512; ++i_pdpt) {
    pdp_table[i_pdpt] = (uint64_t)&page_directory[i_pdpt] | 0x407;
    for (int i_pd = 0; i_pd < 512; ++i_pd) {
      page_directory[i_pdpt][i_pd] = (i_pdpt * kPageSize1G + i_pd * kPageSize2M) | 0x4f7;
    }
  }
    return &pml4_table[0];
//   SetCR3(reinterpret_cast<uint64_t>(&pml4_table[0]));
}


EFI_STATUS
EFIAPI
EfiMain (
    IN EFI_HANDLE        ImageHandle,
    IN EFI_SYSTEM_TABLE  *_SystemTable
    )
{
    uint32_t error;
    struct registers regs;

    SystemTable = _SystemTable;

    wprintf(L"Starting VMXbench ...\r\n");
    // int err = ScanAllBus();
    // wprintf(L"%d\n",err);
    uint8_t ivshm_dev = 0;
    uint8_t dev = 0;
    for(dev=0; dev < 32; dev++){
        uint16_t vendor_id = ReadVendorId(0,dev,0);
        if (vendor_id == 0x1af4){
            ivshm_dev = dev;
            // wprintf(L"bus:%d, dev:%d, func:%d, vendor : %04x\r\n",0,dev,0, vendor_id);
            break;
        }
    }
    // wprintf(L"%d, dev %d\r\n",(ivshm_dev==dev),ivshm_dev);
    // ivshm_dev++;
    uintptr_t bar2 = ReadBar(0,ivshm_dev,0, 2);
    // wprintf(L"bar0:%x, bar1:%x, bar2:%x\r\n",bar0,bar1,bar2);
    input_buf = (void *) (bar2);

    // for(int i = 0; i < 20; i++){
    // wprintf(L"buf[%d] = %x\r\n", i,input_buf[i]);}
    input_buf[3000] = 0xdead;
    // return 1;
    SetupIdentityPageTable();
    SystemTable->BootServices->SetWatchdogTimer(0, 0, 0, NULL);

    // check the presence of VMX support
    uint32_t ecx;
    asm volatile ("cpuid" : "=c" (ecx) : "a" (1) : "ebx", "edx");
    if ((ecx & 0x20) == 0) // CPUID.1:ECX.VMX[bit 5] != 1
	goto error_vmx_not_supported;
    wprintf(L"VMX is supported\r\n");

    // enable VMX 
    wprintf(L"Enable VMX\r\n");
    asm volatile ("mov %%cr4, %0" : "=r" (regs.cr4));
    regs.cr4 |= 0x2000; // CR4.VME[bit 13] = 1
    asm volatile ("mov %0, %%cr4" :: "r" (regs.cr4));

    // enable VMX operation
    wprintf(L"Enable VMX operation\r\n");
    regs.ia32_feature_control = rdmsr(0x3a);
    if ((regs.ia32_feature_control & 0x1) == 0) {
	regs.ia32_feature_control |= 0x5; // firmware should set this
	wrmsr(0x3a, regs.ia32_feature_control);
    } else if ((regs.ia32_feature_control & 0x4) == 0)
	goto error_vmx_disabled;
    
    // apply fixed bits to CR0 & CR4
    uint64_t apply_fixed_bits(uint64_t reg, uint32_t fixed0, uint32_t fixed1)
    {
	reg |= rdmsr(fixed0);
	reg &= rdmsr(fixed1);
	return reg;
    }
    asm volatile ("mov %%cr0, %0" : "=r" (regs.cr0));
    regs.cr0 = apply_fixed_bits(regs.cr0, 0x486, 0x487);
    asm volatile ("mov %0, %%cr0" :: "r" (regs.cr0));
    asm volatile ("mov %%cr4, %0" : "=r" (regs.cr4));
    regs.cr4 = apply_fixed_bits(regs.cr4, 0x488, 0x489);
    asm volatile ("mov %0, %%cr4" :: "r" (regs.cr4));

    // enter VMX operation
    wprintf(L"Enter VMX operation\r\n");
    revision_id = rdmsr(0x480);
    uint32_t *ptr = (uint32_t *)vmxon_region;
    vmxonptr = (uintptr_t)ptr;
    ptr[0] = revision_id;
    asm volatile ("vmxon %1" : "=@ccbe" (error) : "m" (ptr));
    if (error)
	goto error_vmxon;
    asm volatile ("vmxoff");
    asm volatile ("vmxon %1" : "=@ccbe" (error) : "m" (ptr));
    if (error)
	goto error_vmxon;
    // initialize VMCS
    wprintf(L"Initialize VMCS\r\n");
    __builtin_memset(vmcs, 0, 4096);
    ptr = (uint32_t *)vmcs;
    ptr[0] = revision_id;
    asm volatile ("vmclear %1" : "=@ccbe" (error) : "m" (ptr));
    if (error)
	goto error_vmclear;
    asm volatile ("vmptrld %1" : "=@ccbe" (error) : "m" (ptr));
    if (error)
	goto error_vmptrld;
    
    asm volatile ("vmclear %1" : "=@ccbe" (error) : "m" (ptr));
    if (error)
	goto error_vmclear;
    asm volatile ("vmptrld %1" : "=@ccbe" (error) : "m" (ptr));
    if (error)
	goto error_vmptrld;
    
    // vmcall_with_vmcall_number(13);
    // initialize control fields
    uint32_t apply_allowed_settings(uint32_t value, uint64_t msr_index)
    {
	uint64_t msr_value = rdmsr(msr_index);
	value |= (msr_value & 0xffffffff);
	value &= (msr_value >> 32);
	return value;
    }
    uintptr_t IO_BITMAP_ADDR = (uintptr_t)io_bitmap;
    memset(&io_bitmap, 0xff, sizeof(io_bitmap));
    vmwrite(0x2000, IO_BITMAP_ADDR);
    vmwrite(0x2002, IO_BITMAP_ADDR);

    //set up msr bitmap to vmexit from L2 
    uintptr_t MSR_BITMAP_ADDR = (uintptr_t)msr_bitmap;
    memset(&msr_bitmap, 0xff, sizeof(msr_bitmap));
    vmwrite(0x2004, MSR_BITMAP_ADDR);
    wprintf(L"0x%x%x\r\n",vmread(0x2005),vmread(0x2004));
    // wprintf(L"0x%x\r\n",MSR_BITMAP_ADDR);
    // wprintf(L"0x%x\r\n",msr_bitmap);
    wprintf(L"0x480: %0x,%0x\r\n",rdmsr(0x480),rdmsr(0x480)&((uint64_t)0x1<<55));

    // uint32_t pinbased_ctls = apply_allowed_settings(0x28, 0x48d);
    uint32_t pinbased_ctls = apply_allowed_settings(0x7f, 0x481);
    vmwrite(0x482e,0xffffffff);
    vmwrite(0x482e,100000000ull);
    // wprintf(L"0x481: 0x%x\r\n",rdmsr(0x481));
    // wprintf(L"0x48b: 0x%x\r\n",rdmsr(0x48b));

    vmwrite(0x4000, pinbased_ctls);  // Pin-based VM-execution controls

    // wprintf(L"0x48d: 0x%x\n\r",apply_allowed_settings(0x3e, 0x48d));
    // wprintf(L"mixed 0x482 %0x\n",rdmsr(0x48e) |0x10000000|0x80000|0x100000|0x8000|0x10000);
    // wprintf(L"0x482: 0x%x\r\n",rdmsr(0x482));
    // wprintf(L"0x48e: 0x%x\r\n",rdmsr(0x48e));
    // wprintf(L"0x485: 0x%x\r\n",rdmsr(0x485));
    // wprintf(L"apply 0x482 %0x\r\n",apply_allowed_settings(0x0,0x48e));0x1e8c

    // wprintf(L"0x%x\r\n\r",1<<31);
    // wprintf(L"0x%x\r\n\r",0x80000000);

    // vmwrite(0x4002, rdmsr(0x48e) |0x80000000|1<<28|1<<19|1<<20|1<<15|1<<16); // Primary processor-based VM-execution controls
    // vmwrite(0x4002,apply_allowed_settings((0x80000000|0x10000000|0x80000|0x100000| 
    // 0x8000|0x10000|0x1e84|1<<30|1<<29|1<<25|1<<23|1<<21|1<<17|1<<9) ,0x482));
    // Primary processor-based VM-execution controls
    vmwrite(0x4002,apply_allowed_settings((1<<31|
    1<<30|1<<29|1<<28|1<<25|1<<24|1<<23|1<<21|1<<20|1<<19|1<<17|1<<16|1<<15|
    1<<12|1<<11|1<<10|1<<9|1<<7|1<<2),0x482));
    // vmwrite(0x2034,apply_allowed_settings(0x1,0x492));
    vmwrite(0x4004, 0x0);            // Exception bitmap
    vmwrite(0x4004, 0x1<<14|14);            // Exception bitmap
    vmwrite(0x4006, 0xffffffff);            // Exception bitmap
    vmwrite(0x4008, 0xffffffff);            // Exception bitmap
    uint32_t exit_ctls = apply_allowed_settings(0xffffff, 0x483);
    vmwrite(0x400c, exit_ctls);      // VM-exit controls
    uint32_t entry_ctls = apply_allowed_settings(0x93ff, 0x484);
    vmwrite(0x4012, entry_ctls);     // VM-entry controls
    // vmwrite(0x401e, apply_allowed_settings(0x02113d4d,0x48b));
    vmwrite(0x401e, apply_allowed_settings((0x02113d4d|1<<27|1<<26|1<<25|1<<20|
    1<<16|1<<14|1<<13|1<<12|1<<11|1<<10|1<<9|1<<8|1<<6|1<<4|1<<5|1<<3|1<<2) & ~(1<<0),0x48b));
    vmwrite(0x0, 0xffff);
    // vmwrite(0x0, 0x0);
    // vmwrite(0x401e, apply_allowed_settings(0x0213fbff|1<<14,0x48b));
    // enlightened_vmcs213fbf
    // vmwrite(0x401e, apply_allowed_settings(0x02110d4d,0x48b));
    // vmwrite(0x401e, apply_allowed_settings(0x0200000d,0x48b));
    // wprintf(L"efer:0x%x\r\n", rdmsr(0xC0000080));
    // wprintf(L"pin based ctrl 0x4000: 0x%x\r\n",vmread(0x4000));
    // wprintf(L"cpu based ctrl 0x4002: 0x%x\r\n",vmread(0x4002));
    // wprintf(L"vmexit ctrl    0x400c: 0x%x\r\n",vmread(0x400c));
    // wprintf(L"vmentry ctrl   0x4012: 0x%x\r\n",vmread(0x4012));
    // wprintf(L"secondary ctrl 0x401e: 0x%x\r\n",vmread(0x401e)); // secondary
    // wrmsr()
    //x2apic mode*****************************

    //****************************
    // vmwrite(0x401e, 0x0);
    uintptr_t VIRTUAL_APIC_ADDR = (uintptr_t)virtual_apic;
    vmwrite(0x2012, VIRTUAL_APIC_ADDR);
    // uintptr_t vtpr_ptr = vmread(0x2012) + 0x80;
    // uint32_t *vtpr = (uint32_t *)vtpr_ptr;
    // virtual_apic[0x16] = 0x16;
    // virtual_apic[0x80] = 0x80;
    // wprintf(L"0x2012:%x\r\nvtpr: %x\r\n", vmread(0x2012),vtpr[0]);
    // for (int i = 0; i<4096; i++){
    //     virtual_apic[i] = 0xff;
    // }
    uintptr_t APIC_ACCESS_ADDR = (uintptr_t)apic_access;
    vmwrite(0x2014, APIC_ACCESS_ADDR);
    uintptr_t * shadow_ptr = (uintptr_t * )shadow_vmcs2;
    shadow_ptr[0] = rdmsr(0x480)| BX_VMCS_SHADOW_BIT_MASK;
    uintptr_t SHADOW_VMCS_LINK_PTR = (uintptr_t)shadow_vmcs2;
    vmwrite(0x2800, SHADOW_VMCS_LINK_PTR);
        wprintf(L"vmwrite(0x2800, 0x%x);\n", vmread(0x2800));

    SHADOW_VMCS_LINK_PTR = (uintptr_t)vmread_bitmap;
    vmwrite(0x2028, SHADOW_VMCS_LINK_PTR);
    SHADOW_VMCS_LINK_PTR = (uintptr_t)vmwrite_bitmap;
    vmwrite(0x2026, SHADOW_VMCS_LINK_PTR);
    vmwrite(0x2032, 0xffffffffffffffff);
    // memset(&msr_store, 0xff, sizeof(msr_store));
    // memset(&msr_load, 0xff, sizeof(msr_load));
    // memset(&vmentry_msr_load, 0xff, sizeof(vmentry_msr_load));
    for(int i = 0; i < 1024; i++){
        msr_store[i] = 0x10;
        msr_load[i] = 0x10;
        vmentry_msr_load[i] = 0x10;
    }

    uintptr_t msr_store_addr = (uintptr_t)msr_store;
    uintptr_t msr_load_addr = (uintptr_t)msr_load;
    uintptr_t vmentry_msr_load_addr = (uintptr_t)vmentry_msr_load;
    uintptr_t posted_int_desc_addr = (uintptr_t)posted_int_desc;
    vmwrite(0x2006, msr_store_addr);
    vmwrite(0x2008, msr_load_addr);
    vmwrite(0x200a, vmentry_msr_load_addr);
    vmwrite(0x2016, posted_int_desc_addr);
    // vmwrite(0x401e, 0x2177fff);
    // wprintf(L"0x%x\r\n\r",vmread(0x401e));
    // struct MSR_BITMAP MSR_BITMAP1;
    // vmwrite(0x2005, (uint32_t)(MSR_BITMAP_ADDR>>32));
    vmwrite(0x4006,0x0);
    vmwrite(0x4008,-1);
    vmwrite(0x400a, 0x0);

    void vmwrite_gh(uint32_t guest_id, uint32_t host_id, uint64_t value)
    {
	vmwrite(guest_id, value);
	vmwrite(host_id, value);
    }
    
    // 16-Bit Guest and Host State Fields
    asm volatile ("mov %%es, %0" : "=m" (regs.es));
    asm volatile ("mov %%cs, %0" : "=m" (regs.cs));
    asm volatile ("mov %%ss, %0" : "=m" (regs.ss));
    asm volatile ("mov %%ds, %0" : "=m" (regs.ds));
    asm volatile ("mov %%fs, %0" : "=m" (regs.fs));
    asm volatile ("mov %%gs, %0" : "=m" (regs.gs));
    asm volatile ("sldt %0" : "=m" (regs.ldt));
    asm volatile ("str %0" : "=m" (regs.tr));
    vmwrite_gh(0x0800, 0x0c00, regs.es); // ES selector
    vmwrite_gh(0x0802, 0x0c02, regs.cs); // CS selector
    vmwrite_gh(0x0804, 0x0c04, regs.ss); // SS selector
    vmwrite_gh(0x0806, 0x0c06, regs.ds); // DS selector
    vmwrite_gh(0x0808, 0x0c08, regs.fs); // FS selector
    vmwrite_gh(0x080a, 0x0c0a, regs.gs); // GS selector    

    vmwrite(0x080c, regs.ldt);           // Guest LDTR selector
    vmwrite_gh(0x080e, 0x0c0c, regs.tr); // TR selector
    vmwrite(0x0c0c, 0x08); // dummy TR selector for real hardware

    // 64-Bit Guest and Host State Fields
    // vmwrite(0x2800, ~0ULL); // VMCS link pointer
    vmwrite(0x2802, 0);  // Guest IA32_DEBUGCTL
    regs.ia32_efer = rdmsr(0xC0000080);
    vmwrite_gh(0x2806, 0x2c02, regs.ia32_efer); // IA32_EFER

    // 32-Bit Guest and Host State Fields
    asm volatile ("sgdt %0" : "=m" (regs.gdt));
    asm volatile ("sidt %0" : "=m" (regs.idt));
  
    vmwrite(0x4800, get_seg_limit(regs.es)); // Guest ES limit
    vmwrite(0x4802, get_seg_limit(regs.cs)); // Guest CS limit
    vmwrite(0x4804, get_seg_limit(regs.ss)); // Guest SS limit
    vmwrite(0x4806, get_seg_limit(regs.ds)); // Guest DS limit
    vmwrite(0x4808, get_seg_limit(regs.fs)); // Guest FS limit
    vmwrite(0x480a, get_seg_limit(regs.gs)); // Guest GS limit
    vmwrite(0x480c, get_seg_limit(regs.ldt)); // Guest LDTR limit
    uint32_t tr_limit = get_seg_limit(regs.tr);
    if (tr_limit == 0) tr_limit = 0x0000ffff;
    vmwrite(0x480e, tr_limit);       // Guest TR limit
    vmwrite(0x4810, regs.gdt.limit); // Guest GDTR limit
    vmwrite(0x4812, regs.idt.limit); // Guest IDTR limit
    vmwrite(0x4814, get_seg_access_rights(regs.es)); // Guest ES access rights
    vmwrite(0x4816, get_seg_access_rights(regs.cs)); // Guest CS access rights
    vmwrite(0x4818, get_seg_access_rights(regs.ss)); // Guest SS access rights
    vmwrite(0x481a, get_seg_access_rights(regs.ds)); // Guest DS access rights
    vmwrite(0x481c, get_seg_access_rights(regs.fs)); // Guest FS access rights
    vmwrite(0x481e, get_seg_access_rights(regs.gs)); // Guest GS access rights
    uint32_t ldtr_access_rights = get_seg_access_rights(regs.ldt);
    if (ldtr_access_rights == 0) ldtr_access_rights = 0x18082;
    vmwrite(0x4820, ldtr_access_rights); // Guest LDTR access rights
    uint32_t tr_access_rights = get_seg_access_rights(regs.tr);
    if (tr_access_rights == 0) tr_access_rights = 0x0808b;
    vmwrite(0x4822, tr_access_rights); // Guest TR access rights

    vmwrite(0x6000, 0xffffffffffffffff); // CR0 guest/host mask
    vmwrite(0x6002, 0xffffffffffffffff); // CR4 guest/host mask
    vmwrite(0x6004, ~regs.cr0); // CR0 read shadow
    vmwrite(0x6006, ~regs.cr4); // CR4 read shadow
    // Natual-Width Control Fields
    asm volatile ("mov %%cr3, %0" : "=r" (regs.cr3));
    vmwrite_gh(0x6800, 0x6c00, regs.cr0);
    vmwrite_gh(0x6802, 0x6c02, regs.cr3);
    vmwrite_gh(0x6804, 0x6c04, regs.cr4);

    // wprintf(L"cr0 %0x, cr4 %0x\r\n", regs.cr0,regs.cr4);

    vmwrite(0x6806, get_seg_base(regs.es)); // es base
    vmwrite(0x6808, get_seg_base(regs.cs)); // cs base
    vmwrite(0x680a, get_seg_base(regs.ss)); // ss base
    vmwrite(0x680c, get_seg_base(regs.ds)); // ds base
    vmwrite(0x680e, get_seg_base(regs.fs)); // fs base
    vmwrite(0x6810, get_seg_base(regs.gs)); // gs base
    vmwrite(0x6812, get_seg_base(regs.ldt)); // LDTR base
    vmwrite(0x6814, (uint64_t)tss); // TR base

    vmwrite_gh(0x6816, 0x6C0C, regs.gdt.base); // GDTR base
    vmwrite_gh(0x6818, 0x6C0E, regs.idt.base); // IDT base

    vmwrite(0x6C14, (uint64_t)&host_stack[sizeof(host_stack)]); // HOST_RSP
    vmwrite(0x6C16, (uint64_t)__host_entry); // Host RIP
    vmwrite(0x681C, (uint64_t)&guest_stack[sizeof(guest_stack)]); // GUEST_RSP
    vmwrite(0x681E, (uint64_t)guest_entry); // Guest RIP
    // wprintf(L"0x681e: %x\r\n guest_entry: %x\r\n", vmread(0x681e), (uint64_t)guest_entry);
    asm volatile ("pushf; pop %%rax" : "=a" (regs.rflags));
    regs.rflags &= ~0x200ULL; // clear interrupt enable flag
    vmwrite(0x6820, regs.rflags);
    // wprintf(L"rflags %0x\r\n", vmread(0x6820));
    wprintf(L"es %0x, cs %0x, ss %0x, ss %0x, ds %0x, fs%0x, gs %0x, tr %0x, ldtr %0x\r\n",
    regs.es,regs.cs,regs.ss, regs.ds,regs.ds,regs.fs,regs.gs,regs.tr, regs.ldt);    
    
    wprintf(L"access right \r\nes %0x, cs %0x, ss %0x, ss %0x, ds %0x, fs%0x, gs %0x, tr %0x, ldtr %0x\r\n",
    get_seg_access_rights(regs.es),get_seg_access_rights(regs.cs),
    get_seg_access_rights(regs.ss),get_seg_access_rights(regs.ds)
    ,get_seg_access_rights(regs.ds),get_seg_access_rights(regs.fs),
    get_seg_access_rights(regs.gs), tr_access_rights, ldtr_access_rights);
    wprintf(L"limit es %0x, cs %0x\r\n",get_seg_limit(regs.es),get_seg_limit(regs.cs) );
    // wprintf(L"access es %0x, cs %0x\r\n",get_seg_access_rights(regs.es),get_seg_access_rights(regs.cs));
    wprintf(L"base es %0x, cs %0x\r\n",get_seg_base(regs.es),get_seg_base(regs.cs));
    wprintf(L"ldtr limit %x\r\n",get_seg_limit(regs.ldt));
    // vmwrite(0x4820,0x00);
    // wprintf(L"0x4820 ar: %x\r\n", vmread(0x4820));
    // wprintf(L"0x480c limit: %x\r\n", vmread(0x480c));
    // wprintf(L"vmcs_linkptr %x\r\n", vmread(VMCS_64BIT_GUEST_LINK_POINTER));

    wprintf(L"=====================\n");
    uint64_t eptp = (uint64_t)pml4_table;
    wprintf(L"eptp 0x%x\n", eptp);
    // eptp |= 0x18;
    eptp |= 0x5e;
    wprintf(L"eptp 0x%x\n", eptp);
    vmwrite(0x201a, eptp);


    // check vmenter checker
    // vmwrite(0x6820, regs.rflags|(1<<5));
    // vmwrite(0x6820, regs.rflags&(~0x2));
    // vmwrite_gh(0x6800, regs.cr0);
    // vmwrite_gh(0x6802, regs.cr3);
    // vmwrite(0x6804, regs.cr4 &(~BX_CR4_PAE_MASK));
    // wprintf(L"guest dr7 %x\n", vmread(0x681a));
    vmwrite(0x681a, 0xffffffff00000000);
    vmwrite(0x681a, 0x00000000ffffffff);
    
    // vmwrite(0x4012, apply_allowed_settings(0x93ff|1<<14, 0x484));
    // wprintf(L"guest dr7 %x\n", vmread(0x4012));
    // wprintf(L"host PAT %x\n", vmread(0x2c00));
    vmwrite(0x2c00, 0x0000070605040100);
    // wprintf(L"host PAT %x\n", vmread(0x2c00));
    // wprintf(L"guest PAT %x\n", vmread(0x2804));
    // vmwrite(0x2804, 0xffffffff00000000);
    // wprintf(L"guest PAT %x\n", vmread(0x2804));
    // wprintf(L"guest dr7 %x\n", rdmsr(0x484));
    // vmwrite(0x401e, apply_allowed_settings((0x02113d4d|1<<27|1<<26|1<<25|1<<20|
    // 1<<16|1<<14|1<<13|1<<12|1<<11|1<<10|1<<9|1<<8|1<<6|1<<4|1<<5|1<<3|1<<2) 
    // & ~(1<<0|1<<9),0x48b));
    // vmwrite(0x401c,0xff);
    // wprintf(L"tpr threshhold %x\n", vmread(0x401c));
    // vmwrite(0x4002,apply_allowed_settings((1<<31|
    // 1<<30|1<<29|1<<28|1<<25|1<<24|1<<23|1<<21|1<<20|1<<19|1<<17|1<<16|1<<15|
    // 1<<12|1<<11|1<<10|1<<9|1<<7|1<<2),0x482));
    // vmwrite(0x401e, apply_allowed_settings((0x02113d4d|1<<27|1<<26|1<<25|1<<20|
    // 1<<16|1<<14|1<<13|1<<12|1<<11|1<<10|1<<9|1<<8|1<<6|1<<4|1<<5|1<<3|1<<2|1<<23|1<<18) 
    // & ~(1<<0|1<<9),0x48b));    
    // wprintf(L"subpage %x\n", (vmread(0x401e)>>18)&0x1);
    // vmwrite(0x2032, 0x0);
     vmwrite(0x6800, apply_fixed_bits(0, 0x486, 0x487));
     wprintf(L"0x6800 0x%x\n",apply_fixed_bits(0xffffffff, 0x486, 0x487));
     wprintf(L"0x6802 0x%x\n",vmread(0x6802));
     vmwrite(0x4002,0xcd0973fe|1<<21|1<<24|1<<25|1<<15);
    //  vmwrite(0x4000,0x7e|1<<7);
     vmwrite(0x4002,0xf7b9fff6);

    /* 0xcd0973fe 0b11001101000010010111001111111110
       1098 7654 3210 9876 5432 1098 7654 3210
    0b 1100 1101 0000 1001 0111 0011 1111 1110
    */

    /* 0xf7b9fff6 0b11110111101110011111111111110110
       1098 7654 3210 9876 5432 1098 7654 3210
    0b 1111 0111 1011 1001 1111 1111 1111 0110
    */
     
    vmwrite(0x4002,0b11110111101110010111001111111110);
    uint32_t ctrls2 =   1 << 2  |
                        // 1 << 3  |
                        1 << 7  |
                        1 << 9  |
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
    // ctrls2 = 0xc50973fe;
    vmwrite(0x4002,apply_allowed_settings(ctrls2,0x482));
    // wprintf(L"0x%x\n",apply_allowed_settings(ctrls2,0x482));
    // wprintf(L"0x%x\n",apply_allowed_settings(0xcd0973fe,0x482));
    // 0b11000101000010010111001111111110 0xc50973fe
    //  vmwrite(0x4002,0xcd0973fe&~(1<<27));

    // 0x401e, 0x2117b7c 0b10000100010111101101111100
    //    54 3210 9876 5432 1098 7654 3210 
    // 0b 10 0001 0001 0111 1011 0111 1100

    // 0xaeb3fcef 
    // 0b 1010 1110 1011 0011 1111 1100 1110 1111

    vmwrite(0x401e, apply_allowed_settings((0x02113d4d|1<<27|1<<26|1<<25|
    1<<20|1<<16|1<<14|1<<13|1<<12|1<<11|1<<10|1<<9|1<<8|
    1<<6|1<<4|1<<5|1<<3|1<<2) & ~(1<<0),0x48b));

    uint32_t ctrls3 = 0 |
                    //   1 <<  0 |
                    //   1 <<  1 |
                      1 <<  2 |
                      1 <<  3 |
                      1 <<  4 |
                      1 <<  5 |
                      1 <<  6 |
                    //   1 <<  7 |
                      1 <<  8 |
                    //   1 <<  9 |
                      1 << 10 |
                      1 << 11 |
                      1 << 12 |
                      1 << 13 |
                      1 << 14 |
                    //   1 << 15 |
                      1 << 16 |
                    //   1 << 17 |
                    //   1 << 18 |
                    //   1 << 19 |
                      1 << 20 |
                      1 << 22 |
                      1 << 23 |
                      1 << 25;

    vmwrite(0x401e, apply_allowed_settings(ctrls3, 0x48b));
    wprintf(L"401e, 0x%x\n", vmread(0x401e));
 
    // exit ctrl 0x7fffff 0b11111111111111111111111 /22
    // entry ctrl 0x93ff 0b1001001111111111 
    // entry ctrl 0xf3ff 0b1111001111111111 

    exit_ctls = apply_allowed_settings(0xffffff|1<<24|1<<28|1<<29, 0x483);
    wprintf(L"exit ctrl 0x%x\n", exit_ctls);      // VM-exit controls
    entry_ctls = apply_allowed_settings(0x93ff|1<<13|1<<14|1<<15, 0x484);
    vmwrite(0x4012, entry_ctls);
    wprintf(L"entry ctrl 0x%x\n", entry_ctls);      // VM-exit controls
    wprintf(L"guest efer 0x%x\n",vmread(VMCS_64BIT_GUEST_IA32_EFER));

    wprintf(L"vmenrty interr 0x%x\n",vmread(0x4016));
    // vmwrite(0x6820, regs.rflags|1<<17);
    // uint64_t r = 0xffffffffffffffff;
    // r &= ~(0xFFFFFFFFFFC08028);
    // r &= ~(1<<9|1<<8);
    // vmwrite(0x6820, r);

    // wprintf(L"0x4826 0x%x\n", vmread(0x4826));
    wprintf(L"0x4824 0x%x\n", vmread(0x4824));
    vmwrite(0x4824, 0x8);
    vmwrite(0x401c, 0xf);
    virtual_apic[0x80] = 0xff;
    wprintf(L"rdmsr(0x480) = 0x%x // VMX_MSR_VMX_BASIC\n", rdmsr(0x480));
    wprintf(L"rdmsr(0x481) = 0x%x // VMX_MSR_VMX_PINBASED_CTRLS\n", rdmsr(0x481));
    // vmwrite(0x400e, 512);
    // vmwrite(0x400e, 0xe43d0428);
    // vmwrite(0x400e, 0xff);
    // vmwrite(0x400e, 0x1ff);
    // vmwrite(0x400e, 0x200);
    // vmwrite(0x4010, 0x0);
    // vmwrite(0x4010, 0x1);
    // vmwrite(0x4014, 1);
    // wprtinf()
    vmwrite(0x4000, vmread(0x4000)|1<<7);  // Pin-based VM-execution controls

// vmwrite(VMCS_16BIT_GUEST_ES_SELECTOR  + 2*BX_SEG_REG_SS, 0x7d93);
// vmwrite(VMCS_32BIT_GUEST_ES_ACCESS_RIGHTS + 2*BX_SEG_REG_SS, 0xa0f7);
    // wprintf(L"SS ar = %x\n", vmread(0x4818));
    // wprintf(L"CS selector = %x\n", (vmread(0x802)));
    // wprintf(L"SS selector = %x\n", (vmread(0x804)));
    // wprintf(L"SS TYPE = %x\n", (vmread(0x4818))&0xf);
    // wprintf(L"SS DPL = %x\n", (vmread(0x4818)>>5)&0x3);
    // wprintf(L"CS RPL = %x\n", (vmread(0x802))&0x3);
    // wprintf(L"SS RPL = %x\n", (vmread(0x804))&0x3);
//  vmwrite(0x4816,0x1d0dd);
//     0x4000: d7
// 0x4002: e5b9fff6
//  0x401e: 211786c
    // uint64_t a;
    // vmptrst(&a);
    // wprintf(L"ptr %x\r\n", a);
    // wprintf(L"%x, vmxon : %x\r\n",vmcs,vmxon_region);
    // uintptr_t p = a;
    // uint32_t *vp = (uint32_t *)p;
    //     wprintf(L"==========================\n");
    // for(int i = 0; i< 4096;i++){

    //     if (vp[i]!=0)
    //         wprintf(L"vmcs %d 0x%x\n",i,vp[i]);
    // }
    // //////////////////////
    // rdmsr(0x10);
    // wrmsr(0x10, 0x10);
    // vmwrite(0x2806, vmread(0x2806)&(~1<<10));
    //  vmwrite(0x4000,0x7e|1<<7);
// vmwrite(0x0,0xa8b1);
// vmwrite(0x2,0xda);
// vmwrite(0x4,0x4);
// vmwrite(0x800,0x53b9);
// vmwrite(0x802,0x40e4);
// vmwrite(0x804,0x5cac);
// vmwrite(0x806,0x7e29);
// vmwrite(0x808,0x2d13);
// vmwrite(0x80a,0x615);
// vmwrite(0x80c,0x9d8e);
// vmwrite(0x80e,0xbb30);
// vmwrite(0x810,0x3c4d);
// vmwrite(0x812,0x7e64);
// vmwrite(0xc00,0x8);
// vmwrite(0xc02,0x28);
// vmwrite(0xc04,0x8);
// vmwrite(0xc06,0x8);
// vmwrite(0xc08,0x8);
// vmwrite(0xc0a,0x8);
// vmwrite(0xc0c,0x8);
// vmwrite(0x2000,0x1e6f0000);
// vmwrite(0x2002,0x1e6f0000);
// vmwrite(0x2004,0x1e6f1000);
// vmwrite(0x2006,0x1e6f8000);
// vmwrite(0x2008,0x1e6f6000);
// vmwrite(0x200a,0x1e6fa000);
// vmwrite(0x200c,0x34);
// vmwrite(0x200e,0x0);
// vmwrite(0x2010,0x0);
// vmwrite(0x2012,0x1e6f5000);
// vmwrite(0x2014,0x1e6f4000);
// vmwrite(0x2016,0x1e6fc000);
// vmwrite(0x2018,0x0);
// vmwrite(0x201a,0x1e6fd05e);
// vmwrite(0x201c,0x0);
// vmwrite(0x201e,0x0);
// vmwrite(0x2020,0x0);
// vmwrite(0x2022,0x0);
// vmwrite(0x2024,0x0);
// vmwrite(0x2028,0x1e6f2000);
// vmwrite(0x202a,0x50);
// vmwrite(0x202c,0x0);
// vmwrite(0x202e,0x0);
// vmwrite(0x2032,0xffffffffffffffff);
// vmwrite(0x2800,0x1e6ea000);
// vmwrite(0x2802,0x0);
// vmwrite(0x2804,0xb724769bf54f7895);
// vmwrite(0x2806,0x500);
// vmwrite(0x2808,0x0);
// vmwrite(0x280a,0x0);
// vmwrite(0x280c,0x0);
// vmwrite(0x280e,0x0);
// vmwrite(0x2810,0x0);
// vmwrite(0x2c00,0x70605040100);
// vmwrite(0x2c02,0x500);
// vmwrite(0x2c04,0x0);
// vmwrite(0x4000,0xbf); //0b10111111
// vmwrite(0x4000,0x56); //0b01010110
// vmwrite(0x4000,0x56|1<<3|1<<5|1<<7);
// vmwrite(0x4002,0x25a1fd7a);
// vmwrite(0x4002,0xa521fd7a);
// vmwrite(0x4002,0x2581fd7a);
// vmwrite(0x4004,0xc07f5c30);
// vmwrite(0x4006,0x6f1d2c5f);
// vmwrite(0x4008,0xef4eb882);
// vmwrite(0x400a,0x0);
// vmwrite(0x400c,0x13efff);
// vmwrite(0x400e,0xf7);
// vmwrite(0x4010,0x0);
// vmwrite(0x4012,0x93fb);
// vmwrite(0x4014,0x0);
// vmwrite(0x4016,0x80000700);
// vmwrite(0x4018,0x3d5dc1e);
// vmwrite(0x401a,0x341458be);
// vmwrite(0x401c,0x40c8ffa6);
// vmwrite(0x401e,0x200);
// vmwrite(0x4020,0x92);
// vmwrite(0x4022,0x94);
// vmwrite(0x4800,0x53b9);
// vmwrite(0x4802,0x40e4);
// vmwrite(0x4804,0x5cae);
// vmwrite(0x4806,0x7e29);
// vmwrite(0x4808,0x2d13);
// vmwrite(0x480a,0x615);
// vmwrite(0x480c,0xfff);
// vmwrite(0x480e,0xffff);
// vmwrite(0x4810,0x5e28);
// vmwrite(0x4812,0xb345);
// vmwrite(0x4814,0x10fb);
// vmwrite(0x4816,0x209b);
// vmwrite(0x4818,0x4093);
// vmwrite(0x481a,0x1d0f5);
// vmwrite(0x481c,0x14084);
// vmwrite(0x481e,0x1c0a7);
// vmwrite(0x4820,0x100d9);
// vmwrite(0x4822,0xf0eb);
// vmwrite(0x4824,0x8);
// vmwrite(0x4826,0x0);
// vmwrite(0x4828,0xce);
// vmwrite(0x482a,0x478b1fa);
// vmwrite(0x482e,0x48f58c61);
// vmwrite(0x4c00,0x0);
// vmwrite(0x6000,0xdec04c3ffcb7e5c3);
// vmwrite(0x6002,0x9d86f337bdd7abd9);
// vmwrite(0x6004,0x3595a25f751634a5);
// vmwrite(0x6006,0xc5515e8301745f);
// vmwrite(0x6008,0xde);
// vmwrite(0x600a,0xe0);
// vmwrite(0x600c,0xe2);
// vmwrite(0x600e,0xe4);
// vmwrite(0x6800,0x99906c7d);
// vmwrite(0x6802,0x1ff33000);
// vmwrite(0x6804,0x652126);
// vmwrite(0x6806,0x0);
// vmwrite(0x6808,0x0);
// vmwrite(0x680a,0x0);
// vmwrite(0x680c,0x0);
// vmwrite(0x680e,0x0);
// vmwrite(0x6810,0x0);
// vmwrite(0x6812,0x0);
// vmwrite(0x6814,0x1e6ef000);
// vmwrite(0x6816,0x1ff1ce98);
// vmwrite(0x6818,0x1fc07018);
// vmwrite(0x681a,0xd3c0146029a63e30);
// vmwrite(0x681c,0x1e6eef68);
// vmwrite(0x681e,0x1e6d72d0);
// vmwrite(0x6820,0x2);
// vmwrite(0x6822,0x0);
// vmwrite(0x6824,0x0);
// vmwrite(0x6826,0x0);
// vmwrite(0x6c00,0x80000033);
// vmwrite(0x6c02,0x1ff33000);
// vmwrite(0x6c04,0x2668);
// vmwrite(0x6c06,0x0);
// vmwrite(0x6c08,0x0);
// vmwrite(0x6c0a,0x0);
// vmwrite(0x6c0c,0x1ff1ce98);
// vmwrite(0x6c0e,0x1fc07018);
// vmwrite(0x6c10,0x0);
// vmwrite(0x6c12,0x0);
// vmwrite(0x6c14,0x1e6ee000);
// vmwrite(0x6c16,0x1e6d72c3);
        wprintf(L"vmwrite(0x4012,0x%x);\n", vmread(0x4012));
        vmwrite(0x4012, vmread(0x4012)&~(1<<15));
        wprintf(L"vmwrite(0x4012,0x%x);\n", vmread(0x4012));
        wprintf(L"vmwrite(0x2800, 0x%x);\n", vmread(0x2800));
    wprintf(L"---VMCS CHECK START---\r\n");

    enum VMX_error_code is_vmentry_error = VMenterLoadCheckVmControls();
    if (! is_vmentry_error){
        wprintf(L"VMX CONTROLS OK!\r\n");
    }else{
        wprintf(L"VMX CONTROLS ERROR %0d\r\n", is_vmentry_error);
    }
    is_vmentry_error = VMenterLoadCheckHostState();
    if (! is_vmentry_error){
        wprintf(L"HOST STATE OK!\r\n");
    }else{
        wprintf(L"HOST STATE ERROR %0d\r\n", is_vmentry_error);
    }
    uint64_t qualification;
    uint32_t is_error = VMenterLoadCheckGuestState(&qualification);
    if (! is_error){
        wprintf(L"GUEST STATE OK!\r\n");
    }else{
        wprintf(L"GUEST STATE ERROR %0d\r\n", qualification);
        wprintf(L"GUEST STATE ERROR %0d\r\n", is_error);
    }

    for(int i=0; i < vmcs_num; i++){
        restore_vmcs[i] = vmread(vmcs_index[i]);
        // wprintf(L"vmwrite(0x%x, 0x%x);\n", vmcs_index[i], restore_vmcs[i]);
    }
        // vmwrite(0x4824,0x1);
        wprintf(L"vmwrite(0x4012,0x%x);\n", vmread(0x4012));
        vmwrite(0x4012, vmread(0x4012)&~(1<<15));
        wprintf(L"vmwrite(0x4012,0x%x);\n", vmread(0x4012));
        wprintf(L"vmwrite(0x4000, 0x%x);\n", vmread(0x4000));
        wprintf(L"vmwrite(0x4824, 0x%x);\n", vmread(0x4824));
        wprintf(L"vmwrite(0x2, 0x%x);\n", vmread(0x2));
        vmwrite(0x2,0xff);
        // vmwrite(0x2,(uint32_t)-1);
        wprintf(L"vmwrite(0x2, 0x%x);\n", vmread(0x2));
    //  vmwrite(0x4000,0x7e|1<<7);
    // vmwrite(0x2806, vmread(0x2806)&(~1<<10));
    //  vmwrite(VMCS_32BIT_CONTROL_VMENTRY_CONTROLS,vmread(VMCS_32BIT_CONTROL_VMENTRY_CONTROLS)&~(0x200) );
    // vmwrite(VMCS_32BIT_CONTROL_VMENTRY_INTERRUPTION_INFO,vmread(VMCS_32BIT_CONTROL_VMENTRY_INTERRUPTION_INFO)|0x80000000|(6 << 8));
    //   vmwrite(VMCS_32BIT_GUEST_ACTIVITY_STATE, 5);
      
    // vmwrite(0x400c, vmread(0x400c)&~0x00000200);
    // vmwrite(0x401e, vmread(0x401e)|1<<3|1<<13);
    // vmwrite(0x401e, vmread(0x401e)&~2);
    // vmwrite(0x4012, vmread(0x4012)&~(1<<15));
    // vmwrite(0x2014,0);
    // vmwrite(0x2018,1);
    // vmwrite(0x2,4);
    // vmwrite(0x4824,2);
        wprintf(L"vmwrite(0x440e,0x%x);\n", vmread(0x440e));
        vmwrite(0x440e, vmread(0x440e)|0xff);
        wprintf(L"vmwrite(0x440e,0x%x);\n", vmread(0x440e));
    input_buf[4003] = 0;

    if (!__builtin_setjmp(env)) {
	wprintf(L"Launch a VM\r\r\n");
	asm volatile ("cli");
	asm volatile ("vmlaunch" ::: "memory");
	goto error_vmx;
    } else
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
    asm volatile ("vmxoff");
    asm volatile ("mov %%cr4, %0" : "=r" (regs.cr4));
    regs.cr4 &= ~0x2000; // CR4.VME[bit 13] = 0
    asm volatile ("mov %0, %%cr4" :: "r" (regs.cr4));
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
