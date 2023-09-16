#pragma once
/** ***************************************************************************
 * @section section_uefi Section 1. UEFI definitions
 * This section contains several basic UEFI type and function definitions.
 *************************************************************************** */
#include <stdint.h>

#define IN
#define OUT
#define EFIAPI

typedef unsigned short CHAR16, UINT16;
typedef unsigned long long EFI_STATUS;
typedef void *EFI_HANDLE;


//   UINTN                             NumberOfTableEntries;
//   ///
//   /// A pointer to the system configuration tables.
//   /// The number of entries in the table is NumberOfTableEntries.
//   ///
//   EFI_CONFIGURATION_TABLE           *ConfigurationTable;
// } EFI_SYSTEM_TABLE;

// #define NULL		(void *)0
#define EFIERR(a)	(0x8000000000000000 | a)
#define EFI_SUCCESS	0
#define EFI_INVALID_PARAMETER	EFIERR(2)
#define EFI_DEVICE_ERROR	EFIERR(7)

//*******************************************************
// Open Modes
//*******************************************************
#define EFI_FILE_MODE_READ	0x0000000000000001
#define EFI_FILE_MODE_WRITE	0x0000000000000002
#define EFI_FILE_MODE_CREATE	0x8000000000000000
//*******************************************************
// File Attributes
//*******************************************************
#define EFI_FILE_READ_ONLY	0x0000000000000001
#define EFI_FILE_HIDDEN	0x0000000000000002
#define EFI_FILE_SYSTEM	0x0000000000000004
#define EFI_FILE_RESERVED	0x0000000000000008
#define EFI_FILE_DIRECTORY	0x0000000000000010
#define EFI_FILE_ARCHIVE	0x0000000000000020
#define EFI_FILE_VALID_ATTR	0x0000000000000037

#define TPL_NOTIFY   16

typedef struct EFI_INPUT_KEY {
	unsigned short ScanCode;
	unsigned short UnicodeChar;
} EFI_INPUT_KEY;

struct EFI_GUID {
	unsigned int Data1;
	unsigned short Data2;
	unsigned short Data3;
	unsigned char Data4[8];
};

typedef struct EFI_SYSTEM_TABLE {
	char _buf1[44];
	struct EFI_SIMPLE_TEXT_INPUT_PROTOCOL {
		void *_buf;
		unsigned long long (*ReadKeyStroke)(struct EFI_SIMPLE_TEXT_INPUT_PROTOCOL *, struct EFI_INPUT_KEY *);
	} *ConIn;
	void *_buf2;
	struct EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL {
		void *_buf;
		unsigned long long (*OutputString)(struct EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *, unsigned short *);
	} *ConOut;
	char _buf3[24];
	struct EFI_BOOT_SERVICES {
		char _buf1[24];
		char _buf2[56];
		unsigned long long (*CreateEvent)(
			unsigned int Type,
			unsigned long long NotifyTpl,
			void (*NotifyFunction)(void *Event, void *Context),
			void *NotifyContext,
			void *Event);
		char _buf3[232];
		unsigned long long (*LocateProtocol)(struct EFI_GUID *, void *, void **);
	} *BootServices;
} EFI_SYSTEM_TABLE;

struct EFI_GRAPHICS_OUTPUT_BLT_PIXEL {
	unsigned char Blue;
	unsigned char Green;
	unsigned char Red;
	unsigned char Reserved;
};

enum EFI_GRAPHICS_OUTPUT_BLT_OPERATION {
	EfiBltVideoFill,
	EfiBltVideoToBltBuffer,
	EfiBltBufferToVideo,
	EfiBltVideoToVideo,
	EfiGraphicsOutputBltOperationMax
};

enum EFI_GRAPHICS_PIXEL_FORMAT {
	PixelRedGreenBlueReserved8BitPerColor,
	PixelBlueGreenRedReserved8BitPerColor,
	PixelBitMask,
	PixelBltOnly,
	PixelFormatMax
};

struct EFI_GRAPHICS_OUTPUT_PROTOCOL {
	void *_buf;
	unsigned long long (*SetMode)(struct EFI_GRAPHICS_OUTPUT_PROTOCOL *, unsigned int);
	unsigned long long (*Blt)(struct EFI_GRAPHICS_OUTPUT_PROTOCOL *,
				  struct EFI_GRAPHICS_OUTPUT_BLT_PIXEL *,
				  enum EFI_GRAPHICS_OUTPUT_BLT_OPERATION,
				  unsigned long long SourceX, unsigned long long SourceY,
				  unsigned long long DestinationX, unsigned long long DestinationY,
				  unsigned long long Width, unsigned long long Height,
				  unsigned long long Delta);
	struct EFI_GRAPHICS_OUTPUT_PROTOCOL_MODE {
		unsigned int MaxMode;
		unsigned int Mode;
		struct EFI_GRAPHICS_OUTPUT_MODE_INFORMATION {
			unsigned int Version;
			unsigned int HorizontalResolution;
			unsigned int VerticalResolution;
			enum EFI_GRAPHICS_PIXEL_FORMAT PixelFormat;
			struct EFI_PIXEL_BITMASK {
				unsigned int RedMask;
				unsigned int GreenMask;
				unsigned int BlueMask;
				unsigned int ReservedMask;
			} PixelInformation;
			unsigned int PixelsPerScanLine;
		} *Info;
		unsigned long long SizeOfInfo;
		unsigned long long FrameBufferBase;
		unsigned long long FrameBufferSize;
	} *Mode;
};

struct EFI_FILE_PROTOCOL {
	unsigned long long Revision;
	unsigned long long (*Open)(struct EFI_FILE_PROTOCOL *This,
				   struct EFI_FILE_PROTOCOL **NewHandle,
				   unsigned short *FileName,
				   unsigned long long OpenMode,
				   unsigned long long Attributes);
	unsigned long long (*Close)(struct EFI_FILE_PROTOCOL *This);
	unsigned long long (*Delete)(struct EFI_FILE_PROTOCOL *This);
	unsigned long long (*Read)(struct EFI_FILE_PROTOCOL *This,
				   unsigned long long *BufferSize,
				   void *Buffer);
	unsigned long long (*Write)(struct EFI_FILE_PROTOCOL *This,
				    unsigned long long *BufferSize,
				    void *Buffer);
	unsigned long long (*GetPosition)(struct EFI_FILE_PROTOCOL *This,
					  unsigned long long *Position);
	unsigned long long (*SetPosition)(struct EFI_FILE_PROTOCOL *This,
					  unsigned long long Position);
	unsigned long long (*GetInfo)(struct EFI_FILE_PROTOCOL *This,
				      struct EFI_GUID *InformationType,
				      unsigned long long *BufferSize,
				      void *Buffer);
	unsigned long long (*SetInfo)(struct EFI_FILE_PROTOCOL *This,
				      struct EFI_GUID *InformationType,
				      unsigned long long BufferSize,
				      void *Buffer);
	unsigned long long (*Flush)(struct EFI_FILE_PROTOCOL *This);
};

struct EFI_SIMPLE_FILE_SYSTEM_PROTOCOL {
	unsigned long long Revision;
	unsigned long long (*OpenVolume)(
		struct EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *This,
		struct EFI_FILE_PROTOCOL **Root);
};

struct EFI_CPU_PHYSICAL_LOCATION {
	unsigned int Package;
	unsigned int Core;
	unsigned int Thread;
};

struct EFI_PROCESSOR_INFORMATION {
	unsigned long long ProcessorId;
	unsigned int StatusFlag;
	struct EFI_CPU_PHYSICAL_LOCATION Location;
};

struct EFI_MP_SERVICES_PROTOCOL {
	unsigned long long (*GetNumberOfProcessors)(
		struct EFI_MP_SERVICES_PROTOCOL *This,
		unsigned long long *NumberOfProcessors,
		unsigned long long *NumberOfEnabledProcessors);
	unsigned long long (*GetProcessorInfo)(
		struct EFI_MP_SERVICES_PROTOCOL *This,
		unsigned long long ProcessorNumber,
		struct EFI_PROCESSOR_INFORMATION *ProcessorInfoBuffer);
	unsigned long long (*StartupAllAPs)(
		struct EFI_MP_SERVICES_PROTOCOL *This,
		void (*Procedure)(void *ProcedureArgument),
		unsigned char SingleThread,
		void *WaitEvent,
		unsigned long long TimeoutInMicroSeconds,
		void *ProcedureArgument,
		unsigned long long **FailedCpuList);
	unsigned long long (*StartupThisAP)(
		struct EFI_MP_SERVICES_PROTOCOL *This,
		void (*Procedure)(void *ProcedureArgument),
		unsigned long long ProcessorNumber,
		void *WaitEvent,
		unsigned long long TimeoutInMicroseconds,
		void *ProcedureArgument,
		unsigned char *Finished);
	unsigned long long (*SwitchBSP)(
		struct EFI_MP_SERVICES_PROTOCOL *This,
		unsigned long long ProcessorNumber,
		unsigned char EnableOldBSP);
	unsigned long long (*EnableDisableAP)(
		struct EFI_MP_SERVICES_PROTOCOL *This,
		unsigned long long ProcessorNumber,
		unsigned char EnableAP,
		unsigned int *HealthFlag);
	unsigned long long (*WhoAmI)(
		struct EFI_MP_SERVICES_PROTOCOL *This,
		unsigned long long *ProcessorNumber);
};

unsigned short *int_to_unicode(long long val, unsigned char num_digits, unsigned short str[]);
unsigned short *int_to_unicode_hex(unsigned long long val, unsigned char num_digits, unsigned short str[]);
unsigned short *ascii_to_unicode(char ascii[], unsigned char num_digits, unsigned short str[]);

static const EFI_STATUS EFI_NOT_READY = 0x8000000000000006;

struct _EFI_SIMPLE_TEXT_INPUT_PROTOCOL;
typedef struct _EFI_SIMPLE_TEXT_INPUT_PROTOCOL EFI_SIMPLE_TEXT_INPUT_PROTOCOL;

typedef
EFI_STATUS
(EFIAPI *EFI_INPUT_READ_KEY) (
    IN EFI_SIMPLE_TEXT_INPUT_PROTOCOL *This,
    OUT EFI_INPUT_KEY *Key
    );
struct _EFI_SIMPLE_TEXT_INPUT_PROTOCOL {
    void               *a;
    EFI_INPUT_READ_KEY ReadKeyStroke;
};

struct _EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL;
typedef struct _EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL;
typedef
EFI_STATUS
(EFIAPI *EFI_TEXT_STRING) (
    IN EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *This,
    IN CHAR16                          *String
    );
struct _EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL {
    void            *a;
    EFI_TEXT_STRING OutputString;
};

CHAR16 getwchar();
void putws(CHAR16 *str);
void wprintf (const CHAR16 *format, ...);