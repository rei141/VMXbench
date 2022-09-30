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
extern uint64_t current_vmcsptr;
extern uint64_t vmxonptr;
// #include <Library/ShellLib.h>
// #include <Library/UefiShellDebug1CommandsLib/Pci.h>
/** ***************************************************************************
 * @section section_uefi Section 1. UEFI definitions
 * This section contains several basic UEFI type and function definitions.
 *************************************************************************** */

// #define IN
// #define OUT
// #define EFIAPI

// typedef unsigned short CHAR16, UINT16;
// typedef unsigned long long EFI_STATUS;
// typedef void *EFI_HANDLE;

// static const EFI_STATUS EFI_SUCCESS = 0;
// static const EFI_STATUS EFI_NOT_READY = 0x8000000000000006;

// struct _EFI_SIMPLE_TEXT_INPUT_PROTOCOL;
// typedef struct _EFI_SIMPLE_TEXT_INPUT_PROTOCOL EFI_SIMPLE_TEXT_INPUT_PROTOCOL;
// typedef struct {
//     UINT16 ScanCode;
//     CHAR16 UnicodeChar;
// } EFI_INPUT_KEY;
// typedef
// EFI_STATUS
// (EFIAPI *EFI_INPUT_READ_KEY) (
//     IN EFI_SIMPLE_TEXT_INPUT_PROTOCOL *This,
//     OUT EFI_INPUT_KEY *Key
//     );
// struct _EFI_SIMPLE_TEXT_INPUT_PROTOCOL {
//     void               *a;
//     EFI_INPUT_READ_KEY ReadKeyStroke;
// };

// struct _EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL;
// typedef struct _EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL;
// typedef
// EFI_STATUS
// (EFIAPI *EFI_TEXT_STRING) (
//     IN EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *This,
//     IN CHAR16                          *String
//     );
// struct _EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL {
//     void            *a;
//     EFI_TEXT_STRING OutputString;
// };

// typedef struct {
//     char                            a[36];
//     EFI_HANDLE                      ConsoleInHandle;
//     EFI_SIMPLE_TEXT_INPUT_PROTOCOL  *ConIn;
//     EFI_HANDLE                      ConsoleOutHandle;
//     EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *ConOut;
// } EFI_SYSTEM_TABLE;

/*
uint16_t vmcs_index[] = {0x0000,0x0002,0x0004,0x0800,0x0802,0x0804,0x0806,0x0808,0x080a,0x080c,0x080e,0x0810, \
0x0812,0x0c00,0x0c02,0x0c04,0x0c06,0x0c08,0x0c0a,0x0c0c,0x2000,0x2002,0x2004,0x2006,0x2008,0x200a,0x200c, \
0x200e,0x2010,0x2012,0x2014,0x2016,0x2018,0x201a,0x201c,0x201e,0x2020,0x2022,0x2024,0x2028,0x202a,0x202c, \
0x202e,0x2032,0x2400,0x2800,0x2802,0x2804,0x2806,0x2808,0x280a,0x280c,0x280e,0x2810,0x2c00,0x2c02,0x2c04, \
0x4000,0x4002,0x4004,0x4006,0x4008,0x400a,0x400c,0x400e,0x4010,0x4012,0x4014,0x4016,0x4018,0x401a,0x401c, \
0x401e,0x4020,0x4022,0x4400,0x4402,0x4404,0x4406,0x4408,0x440a,0x440c,0x440e,0x4800,0x4802,0x4806,0x4808, \
0x480a,0x480c,0x480e,0x4810,0x4812,0x4814,0x4816,0x4818,0x481a,0x481c,0x481e,0x4820,0x4822,0x4824,0x4826, \
0x4828,0x482a,0x482e,0x4c00,0x6000,0x6002,0x6004,0x6006,0x6008,0x600a,0x600c,0x600e,0x6400,0x6404,0x6402, \
0x6408,0x6406,0x640a,0x6800,0x6802,0x6804,0x6806,0x6808,0x680a,0x680c,0x680e,0x6810,0x6812,0x6814,0x6816, \
0x6818,0x681a,0x681c,0x681e,0x6820,0x6822,0x6824,0x6826,0x6c00,0x6c02,0x6c04,0x6c06,0x6c08,0x6c0a,0x6c0c, \
0x6c0e,0x6c10,0x6c12,0x6c14,0x6c16};
*/

// extern void wprintf (const CHAR16 *format, ...);

// EFI_SYSTEM_TABLE  *SystemTable;

// CHAR16 getwchar()
// {
//     EFI_STATUS status;
//     EFI_INPUT_KEY key;

//     do {
// 	status = SystemTable->ConIn->ReadKeyStroke(SystemTable->ConIn, &key);
//     } while (status == EFI_NOT_READY);
//     return key.UnicodeChar;
// }

// void putws(CHAR16 *str)
// {
//     SystemTable->ConOut->OutputString(SystemTable->ConOut, str);
// }

// void putchar_buffered(CHAR16 c)
// {
//     const int BUFSIZE = 1024;
//     CHAR16 buf[BUFSIZE];
//     static int index = 0;

//     buf[index++] = c;
//     if (index == BUFSIZE - 1 || c == L'\n' || c == L'\0') {
// 	buf[index] = L'\0';
// 	putws(buf);
// 	index = 0;
//     }
// }

// void wprintf (const CHAR16 *format, ...)
// {
//     __builtin_va_list va_list;
//     __builtin_va_start(va_list, format);
//     for (CHAR16 c = *format; (c = *format++) != L'\0';) {
// 	if (c != L'%') {
// 	    putchar_buffered(c);
// 	    continue;
// 	}

// 	CHAR16 prefix;
// 	c = *format++;
// 	if (c == L'0') {
// 	    prefix = L'0';
// 	    c = *format++;
// 	} else
// 	    prefix = L' ';

// 	int len;
// 	if (L'1' <= c && c <= L'9') {
// 	    len = c - L'0';
// 	    c = *format++;
// 	} else
// 	    len = 1;

// 	if (L'0' <= c && c <= L'9') {
// 	    len = len * 10 + (c - L'0');
// 	    c = *format++;
// 	}

// 	uint64_t arg = __builtin_va_arg(va_list, uint64_t);
// 	if (c == L's') {
// 	    CHAR16 *str = (CHAR16 *)arg;
// 	    while (*str != L'\0')
// 		putchar_buffered(*str++);
// 	    continue;
// 	}

// 	int base, digit;
// 	uint64_t divisor;
// 	if (c == L'd') {
// 	    base = 10;
// 	    digit = 20;
// 	    divisor = 10000000000000000000ULL;
// 	} else if (c == L'x') {
// 	    base = 16;
// 	    digit = 16;
// 	    divisor = 0x1000000000000000ULL;
// 	} else
// 	    continue; // not supported yet

// 	int start_output = 0, end_prefix = 0;
// 	for (; digit > 0; digit--) {
// 	    int q = arg / divisor;
// 	    arg %= divisor;

// 	    CHAR16 c = (q > 9 ? L'a' - 10 : L'0') + q;
// 	    if (start_output == 0)
// 		if (c != L'0' || digit <= len)
// 		    start_output = 1;
// 	    if (start_output == 1) {
// 		if (end_prefix == 0)
// 		    if (c != L'0' || digit == 1)
// 			end_prefix = 1;
// 		if (end_prefix == 0)
// 		    c = prefix;
// 		putchar_buffered(c);
// 	    }
// 	    divisor /= base;
// 	}
//     }
//     putchar_buffered(L'\0');
//     __builtin_va_end(va_list);
// }

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
uint16_t vmcs_index[] = {0x0000,0x0002,0x0004,0x0800,0x0802,0x0804,0x0806,0x0808,0x080a,0x080c,0x080e,0x0810, \
0x0812,0x0c00,0x0c02,0x0c04,0x0c06,0x0c08,0x0c0a,0x0c0c,0x2000,0x2002,0x2004,0x2006,0x2008,0x200a,0x200c, \
0x200e,0x2010,0x2012,0x2014,0x2016,0x2018,0x201a,0x201c,0x201e,0x2020,0x2022,0x2024,0x2028,0x202a,0x202c, \
0x202e,0x2032,0x2400,0x2800,0x2802,0x2804,0x2806,0x2808,0x280a,0x280c,0x280e,0x2810,0x2c00,0x2c02,0x2c04, \
0x4000,0x4002,0x4004,0x4006,0x4008,0x400a,0x400c,0x400e,0x4010,0x4012,0x4014,0x4016,0x4018,0x401a,0x401c, \
0x401e,0x4020,0x4022,0x4400,0x4402,0x4404,0x4406,0x4408,0x440a,0x440c,0x440e,0x4800,0x4802,0x4806,0x4808, \
0x480a,0x480c,0x480e,0x4810,0x4812,0x4814,0x4816,0x4818,0x481a,0x481c,0x481e,0x4820,0x4822,0x4824,0x4826, \
0x4828,0x482a,0x482e,0x4c00,0x6000,0x6002,0x6004,0x6006,0x6008,0x600a,0x600c,0x600e,0x6400,0x6404,0x6402, \
0x6408,0x6406,0x640a,0x6800,0x6802,0x6804,0x6806,0x6808,0x680a,0x680c,0x680e,0x6810,0x6812,0x6814,0x6816, \
0x6818,0x681a,0x681c,0x681e,0x6820,0x6822,0x6824,0x6826,0x6c00,0x6c02,0x6c04,0x6c06,0x6c08,0x6c0a,0x6c0c, \
0x6c0e,0x6c10,0x6c12,0x6c14,0x6c16};
/*
uint16_t vmcs_index[] = {0x0000,0x0002,0x0004,0x0800,0x0802,0x0804,0x0806,0x0808,0x080a,0x080c,0x080e,0x0810, \
0x0812,0x0c00,0x0c02,0x0c04,0x0c06,0x0c08,0x0c0a,0x0c0c,0x2000,0x2002,0x2004,0x2006,0x2008,0x200a,0x200c, \
0x200e,0x2010,0x2012,0x2014,0x2016,0x2018,0x201a,0x201c,0x201e,0x2020,0x2022,0x2024,0x2028,0x202a,0x202c, \
0x202e,0x2032,0x2400,0x2800,0x2802,0x2804,0x2806,0x2808,0x280a,0x280c,0x280e,0x2810,0x2c00,0x2c02,0x2c04, \
0x4000,0x4002,0x4004,0x4006,0x4008,0x400a,0x400c,0x400e,0x4010,0x4012,0x4014,0x4016,0x4018,0x401a,0x401c, \
0x401e,0x4020,0x4022,0x4400,0x4402,0x4404,0x4406,0x4408,0x440a,0x440c,0x440e,0x4800,0x4802,0x4806,0x4808, \
0x480a,0x480c,0x480e,0x4810,0x4812,0x4814,0x4816,0x4818,0x481a,0x481c,0x481e,0x4820,0x4822,0x4824,0x4826, \
0x4828,0x482a,0x482e,0x4c00,0x6000,0x6002,0x6004,0x6006,0x6008,0x600a,0x600c,0x600e,0x6400,0x6404,0x6402, \
0x6408,0x6406,0x640a,0x6800,0x6802,0x6804,0x6806,0x6808,0x680a,0x680c,0x680e,0x6810,0x6812,0x6814,0x6816, \
0x6818,0x681a,0x681c,0x681e,0x6820,0x6822,0x6824,0x6826,0x6c00,0x6c02,0x6c04,0x6c06,0x6c08,0x6c0a,0x6c0c, \
0x6c0e,0x6c10,0x6c12,0x6c14,0x6c16};*/
uint16_t l = 54;
uint16_t * input_buf;
char vmcs[4096] __attribute__ ((aligned (4096)));
char vmcs_backup[4096] __attribute__ ((aligned (4096)));
char shadow_vmcs[4096] __attribute__ ((aligned (4096)));
char shadow_vmcs2[4096] __attribute__ ((aligned (4096)));
char vmxon_region[4096] __attribute__ ((aligned (4096)));
    uint32_t get_seg_limit(uint32_t selector)
    {
	uint32_t limit;
        asm volatile ("lsl %1, %0" : "=r" (limit) : "r" (selector));
	return limit;
    }
    uint32_t get_seg_access_rights(uint32_t selector)
    {
	uint32_t access_rights;
	asm volatile ("lar %1, %0" : "=r" (access_rights) : "r" (selector));
	return access_rights >> 8;
    }
    uint64_t get_seg_base(uint32_t selector) { return 0; }
uint64_t count = 0;
void host_entry(uint64_t arg)
{
    // tsc_exit[index] = rdtsc() - arg;
    uint64_t reason = vmread(0x4402);
    if (reason == 18) {
	if (arg == 0) {
        vmcall_with_vmcall_number(13);
        // print_exitreason(reason);
        wprintf(L"goodbye:)\n");
        __builtin_longjmp(env, 1);
	}
            uint16_t flag;
        uint16_t index;
        uint16_t windex;

        uint32_t *ptr;
        uint64_t wvalue;
        uint32_t error;
    if (arg == 1) {
        // input_buf[0x1000] = 0xdead;
        // input_buf[1] = 0xbeaf;
        // unsigned long long count = 0;
        // vmcall_with_vmcall_number(13);


        while(1){
        // wprintf(L"Start fuzzing...%x\r\n");
            // input_buf[3000] = 400;
            // count++;
            if (count %1000 == 0){
                count++;
                wprintf(L"%d\r\n",count);}

            // flag = input_buf[4000];
            while(1){
                flag = input_buf[4000];
                // wprintf(L"%d",flag);
                // SystemTable->BootServices->Stall(0);
                if(flag != 0){
                    break;
                }
            }
            input_buf[4000] = 0;
            // wprintf(L"a\r\n");
            
            // vmwrite(0x401e, 0x211795c);
            // input_buf[0] = 0;
            
            //*******************************koko
            // if(input_buf[0]%2 == 0){
            // // vmwrite(0x401e, 0x211794d);
            //     // __builtin_memset(shadow_vmcs, 0, 4096);
            //     ptr = (uint32_t *)shadow_vmcs;
            //     uint32_t revision_id = rdmsr(0x480);
            //     ptr[0] = revision_id;
            //     asm volatile ("vmclear %1" : "=@ccbe" (error) : "m" (ptr));
            //     if(error){
            //         wprintf(L"vmclear error \n");
            //     }
            //     asm volatile ("vmptrld %1" : "=@ccbe" (error) : "m" (ptr));
            //     if(error){
            //         wprintf(L"vmptrld error \n");
            //     }
            //     // asm volatile ("vmclear %0" :: "m" (ptr));
            //     // asm volatile ("vmptrld %0" :: "m" (ptr));
            // }

            // wprintf(L"Start fuzzing...\r\n");
            // for (int i = 0; i < 50; ++i) {
            //     wprintf(L"input_from_file[%d] = %d\n", i, (int)input_from_file[i]);
            // }

            // wprintf(L"vmread/write start\n");
            for (int i = 0; i < 4092/sizeof(uint16_t); i += 6) {
            // for (int i = 12; i <40/sizeof(uint16_t); i += 6) {
                index = input_buf[i];
            // uint32_t msrindex = (uint64_t)input_buf[i+1]<<16 | (uint64_t)input_buf[i];
            // uint64_t value = (uint64_t)input_buf[i+5]<<48 |(uint64_t)input_buf[i+4]<<32 |(uint64_t)input_buf[i+3]<<16 | (uint64_t)input_buf[i+2];
            // // msrindex = 0xc0000102;
            // msrindex = 0xdeadbeaf;
            // int tmp = rdmsr(msrindex);
            // tmp++;
            // wrmsr(msrindex,value);
        // }
                // if ((index & 0x8000) == 0){
                    windex = (uint64_t)(input_buf[i]%4);
                    wvalue = (uint64_t)input_buf[i+3]<<48 | (uint64_t)input_buf[i+4] << 32 | (uint64_t)input_buf[i+5] << 16| (uint64_t)input_buf[i+2]; 
                    invept_t inv;
                    inv.rsvd = 0;
                    inv.ptr = wvalue;
                    // i.ptr = wvalue;
                    invept((uint64_t)(input_buf[i]%2 + 1),&inv);
                    inv.rsvd = wvalue;
                    inv.ptr = 0;
                    inv.ptr = (uint64_t)input_buf[i+1];
                    invvpid((uint64_t)(input_buf[i]%4),&inv);
                    // continue;
                // }

                windex = input_buf[i + 1];
                wvalue = (uint64_t)input_buf[i + 2];
                // windex = l;
                windex = windex%152;
                // l=150;
                windex = vmcs_index[windex];
                // windex = vmcs_index[windex];
                // /*   
                // if (windex == 0x400a ||windex == 0x681e|| windex == 0x681c||windex == 0x400c || windex == 0x4012 || windex == 0x2802 ||windex ==0x800
                // || windex == 0x440c||windex >= 0x6c00||windex == 0x4002 || windex == 0x4000 || windex == 0xc02 || windex == 0x802 || windex == 0x6802
                // || windex == 0xc00 || windex == 0xc04 || windex == 0xc06 || windex == 0xc08 || windex == 0xc0a 
                // || windex == 0xc0c ||  windex == 0x2c00 || windex == 0x2c02 || windex == 0x4016|| windex == 0x4014 
                // || windex == 0x4010 || windex == 0x400e || windex == 0x2806 || windex ==0x6824 || windex == 0x6804 || windex == 0x6800|| windex == 0x6802){
                //     // wprintf(L"opps\n");
                //     // wprintf(L"PPPPPPP\n");
                //     continue;
                //     // windex = 0x481c; 06
                //     // windex = 0x4014;
                // }
                if (windex == 0x800 || windex == 0x802 || windex == 0x804|| windex == 0x806|| windex == 0x808
                || windex == 0x80a|| windex == 0x80e|| windex == 0xc00|| windex == 0xc02|| windex == 0xc04|| windex == 0xc06
                || windex == 0xc08|| windex == 0xc0a|| windex == 0xc0c|| windex == 0x2004|| windex == 0x2800
                || windex == 0x2802|| windex == 0x2806|| windex == 0x2c02|| windex == 0x4000|| windex == 0x4002
                || windex == 0x400a|| windex == 0x400c|| windex == 0x400e|| windex == 0x4010|| windex == 0x4012
                || windex == 0x4014|| windex == 0x4016|| windex == 0x4800|| windex == 0x4802|| windex == 0x4806
                || windex == 0x4808|| windex == 0x480a|| windex == 0x480e|| windex == 0x4810|| windex == 0x4812
                || windex == 0x4814|| windex == 0x4816|| windex == 0x4818|| windex == 0x481a|| windex == 0x481c
                || windex == 0x481e|| windex == 0x4820|| windex == 0x4822|| windex == 0x4824|| windex == 0x4826
                || windex == 0x440c|| windex == 0x6800|| windex == 0x6802|| windex == 0x6804|| windex == 0x6806
                || windex == 0x6808|| windex == 0x680a|| windex == 0x680c|| windex == 0x680e|| windex == 0x6810
                || windex == 0x6814|| windex == 0x6816|| windex == 0x6818|| windex == 0x681a|| windex == 0x681c
                || windex == 0x6820|| windex == 0x6822|| windex == 0x6824|| windex == 0x6826|| windex == 0x6c00
                || windex == 0x6c02|| windex == 0x6c04|| windex == 0x6c04|| windex == 0x6c06|| windex == 0x6c08
                || windex == 0x6c0a|| windex == 0x6c0c|| windex == 0x6c0e|| windex == 0x6c10|| windex == 0x6c12
                || windex == 0x6c10|| windex == 0x6c16|| windex == 0x6c14|| windex == 0x6000|| windex == 0x6002
                || windex == 0x681e|| windex == 0x401e||windex == 0x401c||windex==0x2014||windex==0x2012||windex == 0x202e
                || windex ==0x2032||windex == 0x6812||windex==	0x2018||windex ==0x2028||windex ==0x2026||windex ==0x2000
                || windex ==0x2002||windex ==0x2c00||windex == 0x2c04||windex == 0x0){
                    // if(index%2 ==0){
                    //     vmwrite(0x4002,vmread(0x4002) & ~(1<<17));
                    // }else{
                    //     vmwrite(0x4002,vmread(0x4002) | (1<<17));
                    // }
                    // wprintf(L"%x,%x",vmread(0x4002),vmread(0x4002)^(1<<17));
                    // vmwrite(0x4002,vmread(0x4002) ^ (1<<17));
                    vmwrite(0x4000, vmread(0x4000) ^(1<<3));  // Pin-based VM-execution controls
                    vmwrite(0x4000, vmread(0x4000) ^(1<<5));  // Pin-based VM-execution controls
                    // vmwrite(0x4002,vmread(0x4002) ^(1<<22));

                    if(index%5 ==0){
                    //“virtualize APIC-accesses” VM-execution control is 1,
                    vmwrite(0x401e,vmread(0x401e) | (1<<0));
                    vmwrite(0x401e,vmread(0x401e) & ~(1<<4));
                    }else if(index%5 ==1){
                    // “virtualize x2APIC mode” VM-execution control is 1,
                    vmwrite(0x401e,vmread(0x401e) & ~(1<<0));
                    vmwrite(0x401e,vmread(0x401e) | (1<<4));
                    }else if (index%5 ==2){
                    // “use TPR shadow” VM-execution control is 0,
                    vmwrite(0x4002, vmread(0x4002) & ~(1<<21));
                    vmwrite(0x401e,vmread(0x401e) & ~(1<<4));
                    vmwrite(0x401e,vmread(0x401e) & ~(1<<8));
                    vmwrite(0x401e,vmread(0x401e) & ~(1<<9));
                    }else if (index%5 ==3){
                    //“virtual-interrupt delivery” VM-execution control is 1
                    vmwrite(0x401e,vmread(0x401e) | (1<<9));
                    vmwrite(0x4000, vmread(0x4000) | (1<<0));  //  External-interrupt
                    vmwrite(0x4002, vmread(0x4002) | (1<<21));
                    }
                    if((vmread(0x401e)&(1<<21)) == 0){
                    vmwrite(0x401e,vmread(0x401e) & ~(1<<4));
                    vmwrite(0x401e,vmread(0x401e) & ~(1<<8));
                    vmwrite(0x401e,vmread(0x401e) & ~(1<<9));
                    }
                    //primary proccesor based
                    vmwrite(0x4002,vmread(0x4002) ^ (1<<25));
                    vmwrite(0x4002,vmread(0x4002) ^ (1<<28));


                    // wprintf(L"%d, vmwrite(%x)\n", l, windex);
                    uint64_t ret = vmread(index);
                    ret = vmread(windex);
                    ret += 1;
                    if (windex == 0x80e){
                        vmwrite(0x80e,wvalue&~(1<<2));}
                    // if (windex == 0x6820){
                    //     // wprintf(L"%0x %0x\n", wvalue,(wvalue&~(1<<15 | 1<<5 | 1<<3))|1<<1);
                    //     vmwrite(0x6820,(wvalue&~(1<<15 | 1<<5 | 1<<3|1<<9|1<<17))|1<<1);
                    // }
                    // wprintf(L"%x %x\n", wvalue, wvalue&~(1<<2));
                    // wprintf(L"%x\n", wvalue);
                    wvalue = wvalue&~(0x3);
                    uint8_t rpl = wvalue &0x3;
                    vmwrite(0x0800, wvalue); // ES selector
                    vmwrite(0x0802, wvalue); // CS selector
                    vmwrite(0x0804, wvalue); // SS selector
                    vmwrite(0x0806, wvalue); // DS selector
                    vmwrite(0x0808, wvalue); // FS selector
                    vmwrite(0x080a, wvalue); // GS selector
                    // vmwrite(0x6806, get_seg_base(wvalue)); // es base
                    // vmwrite(0x6808, get_seg_base(wvalue)); // cs base
                    // vmwrite(0x680a, get_seg_base(wvalue)); // ss base
                    // vmwrite(0x680c, get_seg_base(wvalue)); // ds base
                    // vmwrite(0x680e, get_seg_base(wvalue)); // fs base
                    // vmwrite(0x6810, get_seg_base(wvalue)); // gs base
                    uint32_t get_cs_access_rights(uint32_t selector){
                        selector |= 0x9;
                        selector |= 1<<4;
                        selector &= ~(1<<5 | 1<<6);
                        selector |= 1<<7;
                        selector &= ~(1<<8|1<<9|1<<10|1<<11);
                        selector &= ~(1<<14);
                        selector |= (1<<13);
                        selector |= (1<<15);
                        selector &= 0x0000ffff;
                        return selector;
                    }
                    uint32_t get_ss_access_rights(uint32_t selector){
                        // wprintf(L"rpl %x %x\n", rpl, selector);
                        selector |= 1<<0 | 1<<1;
                        selector &= ~(1<<3);
                        selector |= 1<<4;
                        // selector &= ~(1<<3);
                        // selector &= ~(1<<5 | 1<<6);
                        selector &= ~(1<<5|1<<6);
                        selector |= rpl<<5;
                        // selector |= 1<<5|1<<6;
                        selector |= 1<<7;
                        selector &= ~(1<<8|1<<9|1<<10|1<<11);
                        selector |= (1<<15);
                        selector &= 0x0000ffff;
                        // wprintf(L"%x\n", selector);
                        return selector;

                    }
                    uint32_t get_other_access_rights(uint32_t selector){
                        selector |= 1<<0;
                        if ((selector>>3 & 0x1) == 1)
                            selector |= 1<<1;
                        selector |= 1<<4;
                        // selector &= ~(1<<5 | 1<<6);
                        selector |= rpl<<5;
                        selector |= 1<<7;
                        selector &= ~(1<<8|1<<9|1<<10|1<<11);
                        // selector &= ~(1<<14);
                        selector |= (1<<15);                       
                        selector &= 0x0000ffff;
                        // wprintf(L"%x\n", selector);
                        return selector;

                    }
                    vmwrite(0x4814, get_other_access_rights(wvalue)); // Guest ES access rights
                    vmwrite(0x4816, get_cs_access_rights(wvalue)); // Guest CS access rights
                    vmwrite(0x4818, get_ss_access_rights(wvalue)); // Guest SS access rights
                    vmwrite(0x481a, get_other_access_rights(wvalue)); // Guest DS access rights
                    vmwrite(0x481c, get_other_access_rights(wvalue)); // Guest FS access rights
                    vmwrite(0x481e, get_other_access_rights(wvalue)); // Guest GS access rights
                    // vmwrite(0x4800, 0xffffffff); // Guest ES limit
                    // vmwrite(0x4802, 0xffffffff); // Guest CS limit
                    // vmwrite(0x4804, 0xffffffff); // Guest SS limit
                    // vmwrite(0x4806, 0xffffffff); // Guest DS limit
                    // vmwrite(0x4808, 0xffffffff); // Guest FS limit
                    // vmwrite(0x480a, 0xffffffff); // Guest GS limit  
                    // vmwrite(0x4800, get_seg_limit(wvalue)); // Guest ES limit
                    // vmwrite(0x4802, get_seg_limit(wvalue)); // Guest CS limit
                    // vmwrite(0x4804, get_seg_limit(wvalue)); // Guest SS limit
                    // vmwrite(0x4806, get_seg_limit(wvalue)); // Guest DS limit
                    // vmwrite(0x4808, get_seg_limit(wvalue)); // Guest FS limit
                    // vmwrite(0x480a, get_seg_limit(wvalue)); // Guest GS limit                      
                    continue;
                }
                // */
                if (windex < 0x2000) {
                } else if (windex < 0x4000) {
                    wvalue = (uint64_t)input_buf[i+3]<<48 | (uint64_t)input_buf[i+4] << 32 | (uint64_t)input_buf[i+5] << 16|wvalue; 
                } else if (windex < 0x6000) {
                    wvalue = (uint64_t)input_buf[i+3]<<16 | wvalue;
                } else {
                    wvalue = (uint64_t)input_buf[i+3]<<48 | (uint64_t)input_buf[i+4] << 32 | (uint64_t)input_buf[i+5] << 16|wvalue; 
                }
                    // wprintf(L"%d, vmread(%x)\n", i, index);
                    index = index%152;
                    index = vmcs_index[index];
                    uint64_t ret = vmread(index);
                    ret += 1;
                    // vmwrite(0x4004, 0x0);            // Exception bitmap
                    // vmwrite(0x6000, 0xffffffffffffffff); // CR0 guest/host mask]
                    // wprintf(L"%x\n", windex);
                    vmwrite(windex, wvalue);
                    vmwrite(0x482e,0xffffffff);
                    // wprintf(L"482e: %d", vmread(0x482e));

                    // wprintf(L"%d,%x\n\r", i,windex);
                    // wprintf(L"%d, vmwrite(%x, %x)\r\n", i, windex, wvalue);
                    // ret = rdtsc();
                    // vmwrite(windex1,wvalue);
                    // vmwrite(windex2,wvalue);
                    // vmwrite(windex3, wvalue);
                    // // wprintf(L"%x\n",windex);
                    // vmwrite(windex4,wvalue);
                    // vmwrite(windex5,wvalue);
            }
            // wprintf(L"vmread/write end\n\r");
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
            vmcall_with_vmcall_number(13);
            // if(input_buf[0]%2==0){
                // ptr = (uint32_t *)vmcs;
                // asm volatile ("vmclear %1" : "=@ccbe" (error) : "m" (ptr));
                // if(error){
                //     wprintf(L"vmclear error \n");
                // }
                // // wprintf(L"482e: %d", vmread(0x482e));
                // asm volatile ("vmptrld %1" : "=@ccbe" (error) : "m" (ptr));
                // if(error){
                //     wprintf(L"vmptrld real error \n");
                // }
            // }
            break;
        }
    }
	// print_results();
    uint64_t rip = vmread(0x681E); // Guest RIP
    uint64_t len = vmread(0x440C); // VM-exit instruction length
    // wprintf(L"rip %x, len %d\n\r", rip , len);


    // vmwrite(0x681E, rip + len);
    // wprintf(L"%x\n", vmread(0x681e));
    // // __builtin_longjmp(env, 1);
    vmwrite(0x681E, rip + len);
    asm volatile("vmresume\n\t");
    wprintf(L"VMRESUME failed: \r\n");
    wprintf(L"0x4000: %x\r\n0x4002: %x\r\n 0x401e: %x\r\n",vmread(0x4000),vmread(0x4002),vmread(0x401e));
    // wprintf(L"%x %d\r\n", windex, l);

    wprintf(L"Error Number is %d\r\n", vmread(0x4400));
    __builtin_longjmp(env, 1);
    // return;
    // uint64_t tmp;
    // vmptrst(&tmp);
    // wprintf(L"%x\n",tmp);
    // wprintf(L"%x\n",vmcs[0x6000]);
    // wprintf(L"%x\n",vmcs[0b0100000000011110]);
    // for (int i = 0; i < 4096; i++){
        // wprintf(L"%x \n",vmcs[i]);
    //     vmcs_backup[i] = vmcs[i];
    // }
    // wprintf(L"a %d \r\n",vmread(0x401e));

    asm volatile ("vmxoff");
    // // for (int i = 0; i < 4096; i++){
    // //     if (vmcs_backup[i] != vmcs[i]){
    // //         wprintf(L"%d error \n",i);
    // //     }
    // // }
    uint64_t cr0,cr4;

    asm volatile ("mov %%cr4, %0" : "=r" (cr4));
    cr4 |= 0x2000; // CR4.VME[bit 13] = 1
    asm volatile ("mov %0, %%cr4" :: "r" (cr4));

    // enable VMX operation
    // wprintf(L"Enable VMX operation\r\n");
    uint64_t ia32_feature_control = rdmsr(0x3a);
    if ((ia32_feature_control & 0x1) == 0) {
	ia32_feature_control |= 0x5; // firmware should set this
	wrmsr(0x3a, ia32_feature_control);
    } else if ((ia32_feature_control & 0x4) == 0)
	wprintf(L"cannot enable vmx\r\n");

    uint64_t apply_fixed_bits(uint64_t reg, uint32_t fixed0, uint32_t fixed1)
    {
	reg |= rdmsr(fixed0);
	reg &= rdmsr(fixed1);
	return reg;
    }
    asm volatile ("mov %%cr0, %0" : "=r" (cr0));
    cr0 = apply_fixed_bits(cr0, 0x486, 0x487);
    asm volatile ("mov %0, %%cr0" :: "r" (cr0));
    asm volatile ("mov %%cr4, %0" : "=r" (cr4));
    cr4 = apply_fixed_bits(cr4, 0x488, 0x489);
    asm volatile ("mov %0, %%cr4" :: "r" (cr4));
    uint32_t revision_id = rdmsr(0x480);
    ptr = (uint32_t *)vmxon_region;
    ptr[0] = revision_id;
        // wprintf(L"goodbye:)\r\n");

    asm volatile ("vmxon %1" : "=@ccbe" (error) : "m" (ptr));
    if (error){
        wprintf(L"vmxon failed\r\n");
    }
    ptr = (uint32_t *)vmcs;
    
    ptr[0] = revision_id;
    asm volatile ("vmclear %1" : "=@ccbe" (error) : "m" (ptr));
    if (error){
        wprintf(L"vmclear failed\r\n");
    }
    asm volatile ("vmptrld %1" : "=@ccbe" (error) : "m" (ptr));
    if (error){
        wprintf(L"vmxptr failed\r\n");
    }
    // uint32_t apply_allowed_settings(uint32_t value, uint64_t msr_index)
    // {
	// uint64_t msr_value = rdmsr(msr_index);
	// value |= (msr_value & 0xffffffff);
	// value &= (msr_value >> 32);
	// return value;
    // }
    // vmwrite(0x401e, apply_allowed_settings(0x02113d4d|1<<14,0x48b));
    // wprintf(L"%x\r\n",vmread(0x401e));
    // for (int i = 0; i < 4096; i++){
    //     vmcs[i] = vmcs_backup[i];
    // }
	// asm volatile ("vmlaunch" ::: "memory");
    //     // wprintf(L"vmxptr failed\r\n");
    // wprintf(L"0x4000: 0x%x\r\n\r",vmread(0x4000));
    // wprintf(L"0x4002: 0x%x\r\n\r",vmread(0x4002));
    // wprintf(L"0x401e: 0x%x\r\n\r",vmread(0x401e));
    //     wprintf(L"Error Number is %d\r\r\n", vmread(0x4400));

    vmwrite(0x681E, rip + len);
    // asm volatile("vmresume\n\t");
    // wprintf(L"%x\r\n", vmread(0x681e));
    // wprintf(L"%x\r\n", vmread(0x440c));
    // rip = vmread(0x681E); // Guest RIP
    // len = vmread(0x440C); // VM-exit instruction length
    // wprintf(L"rip %x, len %d\n\r", rip , len);


    // vmwrite(0x681E, rip + len);
	asm volatile ("vmlaunch" ::: "memory");
    wprintf(L"VMLAUNCH failed: \r\n");
    // wprintf(L"%x %d\r\n", windex, l);

    wprintf(L"Error Number is %d\r\n", vmread(0x4400));
    __builtin_longjmp(env, 1);

    } else {
    uint64_t rip = vmread(0x681E); // Guest RIP
    uint64_t len = vmread(0x440C); // VM-exit instruction length
    vmwrite(0x681E, rip + len);
	// print_exitreason(reason);
    }
}

void __host_entry(void);
void _host_entry(void)
{
    // asm volatile (
	// "__host_entry:\n\t"
	// "call host_entry\n\t"
	// );
    // // // wprintf(L"vmresume\n");
    // int ret=0;
    // // wprintf(L"%0x\n", ret);
    // asm volatile (
	// "vmresume\n\t":"=&a"(ret)
	// );       
    // // print_exitreason();
    // wprintf(L"%0x\n", ret);
    // asm volatile (
	// "loop: jmp loop\n\t"
	// );    
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
        // vmcall_with_vmcall_number(13);
    // wprintf(L"start fuzz\n");
        // uint16_t flag;
        // wprintf(L"start fuzz\r\n");
    while(1){
        // SystemTable->BootServices->Stall(10);
        vmcall(1);
        input_buf[4001] = 1;
        uint64_t dummy;
        uint64_t zero = 0;
        __invpcid(0, 0, 0);
        // asm volatile ("tpause":::);
        // asm volatile ("encls":::);
        // void register_state=0;
        asm volatile ("wbnoinvd":::);
        // asm volatile ("invpcid");
        asm volatile ("pause");
        // asm volatile ("pconfig");
        asm volatile ("monitor");
        asm volatile ("mwait");
        // asm volatile ("getsec":::);
        asm volatile ("rdtsc");
        asm volatile ("rdtscp");
        asm volatile ("rdrand %0" : "+c" (zero) : : "%rax");
        asm volatile ("rdseed %0" : "+c" (zero) : : "%rax");
        asm volatile ("rdpmc": "+c" (zero) : : "%rax");
        asm volatile ("wbinvd":::);
        asm volatile ("invd":::);

        uint32_t ecx;

        asm volatile ("cpuid" : "=c" (ecx) : "a" (1) : "ebx", "edx");

        // l++;
        // // uint64_t tmp = rdmsr(0xdeadbeaf);
        for(int dev=0; dev < 32; dev++){
        uint16_t vendor_id = ReadVendorId(0,dev,0);
        vendor_id++;
            // wprintf(L"bus:%d, dev:%d, func:%d, vendor : %04x\n\r",0,dev,0, vendor_id);
        }
        asm volatile ("hlt");
        asm volatile ("invlpg %0" : :"m"(zero));
        // // // for (int i = 0; i < 1000/sizeof(uint16_t); i += 6) {
        // // zero = (uint64_t)input_buf[i+3]<<48 | (uint64_t)input_buf[i+2] << 32 | (uint64_t)input_buf[i+1] << 16| (uint64_t)input_buf[i];
        // // zero = (uint64_t)input_buf[3]<<48 | (uint64_t)input_buf[2] << 32 | (uint64_t)input_buf[1] << 16| (uint64_t)input_buf[0];
        asm volatile ("movq %0, %%cr0" : "+c" (zero) : : "%rax");

        // wprintf(L"mov to cr3\r\n");
        // zero = 0x0;
        asm volatile ("movq %0, %%cr3" : "+c" (zero) : : "%rax");

        // wprintf(L"mov to cr4\r\n");
        // zero = 0x0;
        asm volatile ("movq %0, %%cr4" : "+c" (zero) : : "%rax");

        // wprintf(L"mov to cr8\r\n");
        // zero = 0x0;
        asm volatile ("movq %0, %%cr8" : "+c" (zero) : : "%rax");

        // // wprintf(L"clts\r\n");
        asm volatile ("clts");

        // // wprintf(L"mov from cr3\r\n");

        asm volatile ("movq %%cr3, %0" : "=c" (dummy) : : "%rbx");

        // // wprintf(L"mov from cr8\r\n");
        asm volatile ("movq %%cr8, %0" : "=c" (dummy) : : "%rbx", "%rsi");
        asm volatile ("movq %0, %%dr0" : "+c" (zero) : : "%rax");
        asm volatile ("movq %0, %%dr1" : "+c" (zero) : : "%rax");
        asm volatile ("movq %0, %%dr2" : "+c" (zero) : : "%rax");
        asm volatile ("movq %0, %%dr3" : "+c" (zero) : : "%rax");
        asm volatile ("movq %0, %%dr4" : "+c" (zero) : : "%rax");
        asm volatile ("movq %0, %%dr5" : "+c" (zero) : : "%rax");
        asm volatile ("movq %0, %%dr6" : "+c" (zero) : : "%rax");
        asm volatile ("movq %0, %%dr7" : "+c" (zero) : : "%rax");

        asm volatile ("movq %%dr0, %0" : "=c" (dummy) : : "%rbx");
        asm volatile ("movq %%dr1, %0" : "=c" (dummy) : : "%rbx");
        asm volatile ("movq %%dr2, %0" : "=c" (dummy) : : "%rbx");
        asm volatile ("movq %%dr3, %0" : "=c" (dummy) : : "%rbx");
        asm volatile ("movq %%dr4, %0" : "=c" (dummy) : : "%rbx");
        asm volatile ("movq %%dr5, %0" : "=c" (dummy) : : "%rbx");
        asm volatile ("movq %%dr6, %0" : "=c" (dummy) : : "%rbx");
        asm volatile ("movq %%dr7, %0" : "=c" (dummy) : : "%rbx");
        // wprintf(L"lmsw\r\n");
        uint16_t zero16 = 0;
        asm volatile ("lmsw %0" : "+c" (zero16) : : "%rdi");
        uint32_t index;
        uint64_t value;
        int tmp;
        for (int i = 0; i < 4092/sizeof(uint16_t); i += 6) {
        // for (int i = 0; i < 4092/sizeof(uint16_t); i += 6) {
            if(input_buf[i]%2 == 0){
                index = (uint64_t)input_buf[i];
            }else{
                index = (uint64_t)0xc000<<16 | (uint64_t)input_buf[i];
            }
            value = (uint64_t)input_buf[i+5]<<48 |(uint64_t)input_buf[i+4]<<32 |(uint64_t)input_buf[i+3]<<16 | (uint64_t)input_buf[i+2];
            // index = 0xc0000102;
            tmp = rdmsr(index);
            tmp++;
            wrmsr(index,value);
            // uint32_t ecx;
            // asm volatile ("cpuid" : "=c" (ecx) : "a" (index) : "ebx", "edx");
            asm volatile ("mov %0, %%dx" ::"r" (input_buf[i]));
            asm volatile ("mov %0, %%eax" ::"r" ((uint32_t)input_buf[i+1]));
            asm volatile ("out %eax, %dx");
            asm volatile("mov %0, %%dx" ::"r"(input_buf[i]));
            asm volatile("in %dx, %eax");

        }
        asm volatile ("invlpg %0" : :"m"(zero));

        // tmp++;
        // wprintf(L"%x\r\n",tmp);
        // wprintf(L"mov to cr0\r\r\n");

    }

    // for(int i = 0; i < 200; i++){
	    // vmcall(1);
        // l++;
    // }
    // __builtin_longjmp(env, 1);
    wprintf(L"returned\n\r");
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
            wprintf(L"bus:%d, dev:%d, func:%d, vendor : %04x\r\n",0,dev,0, vendor_id);
            break;
        }
    }
    wprintf(L"%d, dev %d\r\n",(ivshm_dev==dev),ivshm_dev);
    // ivshm_dev++;
    uintptr_t bar0 = ReadBar(0,dev,0, 0);
    uintptr_t bar1 = ReadBar(0,dev,0, 1);
    uintptr_t bar2 = ReadBar(0,dev,0, 2);
    wprintf(L"bar0:%x, bar1:%x, bar2:%x\r\n",bar0,bar1,bar2);
    input_buf = (void *) (bar2);

    for(int i = 0; i < 20; i++){
    wprintf(L"buf[%d] = %x\r\n", i,input_buf[i]);}
    input_buf[3000] = 0xdead;
    // return 1;

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
    uint32_t revision_id = rdmsr(0x480);
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
    current_vmcsptr = (uintptr_t)ptr;
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
    
    vmcall_with_vmcall_number(13);
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
    wprintf(L"0x481: 0x%x\r\n",rdmsr(0x481));
    wprintf(L"0x48b: 0x%x\r\n",rdmsr(0x48b));

    vmwrite(0x4000, pinbased_ctls);  // Pin-based VM-execution controls
    // uint32_t procbased_ctls = apply_allowed_settings(0x8401e9f2, 0x48e);
    // uint32_t procbased_ctls = apply_allowed_settings(0xfbf99e8c, 0x482);
    // wrmsr(0x48e,rdmsr(0x48e)|0x80000000);
    // wprintf(L"0x48d: 0x%x\n\r",apply_allowed_settings(0x3e, 0x48d));
    // wprintf(L"mixed 0x482 %0x\n",rdmsr(0x48e) |0x10000000|0x80000|0x100000|0x8000|0x10000);
    wprintf(L"0x482: 0x%x\r\n",rdmsr(0x482));

    wprintf(L"0x48e: 0x%x\r\n",rdmsr(0x48e));
    wprintf(L"apply 0x48e %0x\r\n",apply_allowed_settings(0x10000000|0x80000|0x100000|0x8000|0x10000,0x48e));
    wprintf(L"apply 0x48e %0x\r\n",apply_allowed_settings(0x80000000|0x10000000|0x80000|0x100000|0x8000|0x10000|0x1e8c,0x48e));
    // wprintf(L"apply 0x482 %0x\r\n",apply_allowed_settings(0x0,0x48e));0x1e8c

    // wprintf(L"0x%x\r\n\r",1<<31);
    // wprintf(L"0x%x\r\n\r",0x80000000);

    // vmwrite(0x4002, rdmsr(0x48e) |0x80000000|1<<28|1<<19|1<<20|1<<15|1<<16); // Primary processor-based VM-execution controls
    // vmwrite(0x4002,apply_allowed_settings((0x80000000|0x10000000|0x80000|0x100000| 
    // 0x8000|0x10000|0x1e84|1<<30|1<<29|1<<25|1<<23|1<<21|1<<17|1<<9) ,0x482));
    vmwrite(0x4002,apply_allowed_settings((1<<31|
    1<<30|1<<29|1<<28|1<<25|1<<24|1<<23|1<<21|1<<20|1<<19|1<<17|1<<16|1<<15|
    1<<12|1<<11|1<<10|1<<9|1<<7|1<<2),0x482));
    // vmwrite(0x4002,apply_allowed_settings((0x80000000|0x10000000|0x80000|0x100000| 
    // 0x8000|0x10000|0x1e84|1<<30|1<<29|1<<25|1<<23|1<<17|1<<9) & ~(1<21),0x482));
    // wprintf(L"0x492 %x \r\n",rdmsr(0x492));
    // wprintf(L"0x492 %x \r\n",apply_allowed_settings(0x1,0x492));

    // vmwrite(0x2034,apply_allowed_settings(0x1,0x492));
    // vmwrite(0x4002,apply_allowed_settings(0x10000000|0x80000|0x100000|0x8000|0x10000|0x1e84,0x482));
    // vmwrite(0x4002,apply_allowed_settings(0x80018880,0x48e));
    
    // vmwrite(0x4002, rdmsr(0x48e) |0x10000000|0x80000|0x100000|0x8000|0x10000); // Primary processor-based VM-execution controls
    // vmwrite(0x4002, rdmsr(0x48e) |0x10000000|0x80000|0x100000|0x8000|0x10000); // Primary processor-based VM-execution controls
    // vmwrite(0x4002, 0xfbf91e8c); // Primary processor-based VM-execution controls

    vmwrite(0x4004, 0x0);            // Exception bitmap
    uint32_t exit_ctls = apply_allowed_settings(0xffffff, 0x483);
    vmwrite(0x400c, exit_ctls);      // VM-exit controls
    uint32_t entry_ctls = apply_allowed_settings(0x93ff, 0x484);
    vmwrite(0x4012, entry_ctls);     // VM-entry controls
    // vmwrite(0x401e, apply_allowed_settings(0x02113d4d,0x48b));
    vmwrite(0x401e, apply_allowed_settings((0x02113d4d|1<<27|1<<26|1<<25|1<<20|
    1<<16|1<<14|1<<13|1<<12|1<<11|1<<10|1<<9|1<<8|1<<6|1<<4|1<<5|1<<3|1<<2) & ~(1<<0),0x48b));
    vmwrite(0x0, 0xffff);
    // vmwrite(0x401e, apply_allowed_settings(0x0213fbff|1<<14,0x48b));
    // enlightened_vmcs213fbf
    // vmwrite(0x401e, apply_allowed_settings(0x02110d4d,0x48b));
    // vmwrite(0x401e, apply_allowed_settings(0x0200000d,0x48b));
    wprintf(L"efer:0x%x\r\n", rdmsr(0xC0000080));
    wprintf(L"0x4000: 0x%x\r\n",vmread(0x4000));
    wprintf(L"0x4002: 0x%x\r\n",vmread(0x4002));
    wprintf(L"0x400c: 0x%x\r\n",vmread(0x400c));
    wprintf(L"0x4012: 0x%x\r\n",vmread(0x4012));
    wprintf(L"0x401e: 0x%x\r\n",vmread(0x401e)); // secondary
// 0x4000: 7f
// 0x4002: f7b9fff6
//  0x401e: 2117a6c

// 0x4002: f799fff6
//  0x401e: 211787c
    // vmwrite(0x4000,0x7f);
    // vmwrite(0x4002, 0xf799fff6);
    // vmwrite(0x401e, 0x211787c);

                    //     if(index%5 ==0){
                    // //“virtualize APIC-accesses” VM-execution control is 1,
                    // vmwrite(0x401e,vmread(0x401e) | (1<<0));
                    // vmwrite(0x401e,vmread(0x401e) & ~(1<<4));
                    // }else if(index%5 ==1){
                    // // “virtualize x2APIC mode” VM-execution control is 1,
                    // vmwrite(0x401e,vmread(0x401e) & ~(1<<0));
                    // vmwrite(0x401e,vmread(0x401e) | (1<<4));
                    // }else if (index%5 ==2){
                    // // “use TPR shadow” VM-execution control is 0,
                    // vmwrite(0x4002, vmread(0x4002) & ~(1<<21));
                    // vmwrite(0x401e,vmread(0x401e) & ~(1<<4));
                    // vmwrite(0x401e,vmread(0x401e) & ~(1<<8));
                    // vmwrite(0x401e,vmread(0x401e) & ~(1<<9));
                    // }else if (index%5 ==3){
                    // //“virtual-interrupt delivery” VM-execution control is 1
                    // vmwrite(0x401e,vmread(0x401e) | (1<<9));
                    // vmwrite(0x4000, vmread(0x4000) | (1<<0));  //  External-interrupt
                    // vmwrite(0x4002, vmread(0x4002) | (1<<21));
                    // }
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
    SHADOW_VMCS_LINK_PTR = (uintptr_t)vmread_bitmap;
    vmwrite(0x2028, SHADOW_VMCS_LINK_PTR);
    SHADOW_VMCS_LINK_PTR = (uintptr_t)vmwrite_bitmap;

    vmwrite(0x2026, SHADOW_VMCS_LINK_PTR);
    vmwrite(0x2032, 0xffffffffffffffff);
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

    wprintf(L"cr0 %0x, cr4 %0x\r\n", regs.cr0,regs.cr4);

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
    wprintf(L"0x681e: %x\r\n guest_entry: %x\r\n", vmread(0x681e), (uint64_t)guest_entry);
    asm volatile ("pushf; pop %%rax" : "=a" (regs.rflags));
    regs.rflags &= ~0x200ULL; // clear interrupt enable flag
    vmwrite(0x6820, regs.rflags);

    wprintf(L"rflags %0x\r\n", vmread(0x6820));
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
    // vmwrite(0x4820,0x10082);
    wprintf(L"0x4820 ar: %x\r\n", vmread(0x4820));
    wprintf(L"0x480c limit: %x\r\n", vmread(0x480c));
    wprintf(L"vmcs_linkptr %x\r\n", vmread(VMCS_64BIT_GUEST_LINK_POINTER));
    uint64_t a;
    vmptrst(&a);
    wprintf(L"ptr %x\r\n", a);
    wprintf(L" %x, vmxon : %x\r\n",vmcs,vmxon_region);
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
    // for (int i = 0; i < 4096; i++){
    //     vmcs_backup[i] = vmcs[i];
    //     wprintf(L"%d: %x, vmxon %d: %x\r\n",i,vmcs[i],i,vmxon_region[i]);
    // }
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
