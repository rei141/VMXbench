#include "uefi.h"

EFI_SYSTEM_TABLE  *SystemTable;

CHAR16 getwchar()
{
    EFI_STATUS status;
    EFI_INPUT_KEY key;

    do {
	status = SystemTable->ConIn->ReadKeyStroke(SystemTable->ConIn, &key);
    } while (status == EFI_NOT_READY);
    return key.UnicodeChar;
}

void putws(CHAR16 *str)
{
    SystemTable->ConOut->OutputString(SystemTable->ConOut, str);
}

void putchar_buffered(CHAR16 c)
{
    const int BUFSIZE = 1024;
    CHAR16 buf[BUFSIZE];
    static int index = 0;

    buf[index++] = c;
    if (index == BUFSIZE - 1 || c == L'\n' || c == L'\0') {
	buf[index] = L'\0';
	putws(buf);
	index = 0;
    }
}

void wprintf (const CHAR16 *format, ...)
{
    __builtin_va_list va_list;
    __builtin_va_start(va_list, format);
    for (CHAR16 c = *format; (c = *format++) != L'\0';) {
	if (c != L'%') {
	    putchar_buffered(c);
	    continue;
	}

	CHAR16 prefix;
	c = *format++;
	if (c == L'0') {
	    prefix = L'0';
	    c = *format++;
	} else
	    prefix = L' ';

	int len;
	if (L'1' <= c && c <= L'9') {
	    len = c - L'0';
	    c = *format++;
	} else
	    len = 1;

	if (L'0' <= c && c <= L'9') {
	    len = len * 10 + (c - L'0');
	    c = *format++;
	}

	uint64_t arg = __builtin_va_arg(va_list, uint64_t);
	if (c == L's') {
	    CHAR16 *str = (CHAR16 *)arg;
	    while (*str != L'\0')
		putchar_buffered(*str++);
	    continue;
	}

	int base, digit;
	uint64_t divisor;
	if (c == L'd') {
	    base = 10;
	    digit = 20;
	    divisor = 10000000000000000000ULL;
	} else if (c == L'x') {
	    base = 16;
	    digit = 16;
	    divisor = 0x1000000000000000ULL;
	} else
	    continue; // not supported yet

	int start_output = 0, end_prefix = 0;
	for (; digit > 0; digit--) {
	    int q = arg / divisor;
	    arg %= divisor;

	    CHAR16 c = (q > 9 ? L'a' - 10 : L'0') + q;
	    if (start_output == 0)
		if (c != L'0' || digit <= len)
		    start_output = 1;
	    if (start_output == 1) {
		if (end_prefix == 0)
		    if (c != L'0' || digit == 1)
			end_prefix = 1;
		if (end_prefix == 0)
		    c = prefix;
		putchar_buffered(c);
	    }
	    divisor /= base;
	}
    }
    putchar_buffered(L'\0');
    __builtin_va_end(va_list);
}


unsigned short *int_to_unicode(long long val, unsigned char num_digits, unsigned short str[])
{
	unsigned char digits_base = 0;
	char i;

	if (val < 0) {
		str[digits_base++] = L'-';
		val *= -1;
	}

	for (i = num_digits - 1; i >= 0; i--) {
		str[digits_base + i] = L'0' + (val % 10);
		val /= 10;
	}

	str[digits_base + num_digits] = L'\0';

	return str;
}

unsigned short *int_to_unicode_hex(unsigned long long val, unsigned char num_digits, unsigned short str[])
{
	short i;
	unsigned short v;

	for (i = num_digits - 1; i >= 0; i--) {
		v = (unsigned short)(val & 0x0f);
		if (v < 0xa)
			str[i] = L'0' + v;
		else
			str[i] = L'A' + (v - 0xa);
		val >>= 4;
	}

	str[num_digits] = L'\0';

	return str;
}

unsigned short *ascii_to_unicode(char ascii[], unsigned char num_digits, unsigned short str[])
{
	unsigned char i;

	for (i = 0; i < num_digits; i++) {
		if (ascii[i] == '\0') {
			break;
		}

		if ('0' <= ascii[i] && ascii[i] <= '9')
			str[i] = L'0' + (ascii[i] - '0');
		else if ('A' <= ascii[i] && ascii[i] <= 'Z')
			str[i] = L'A' + (ascii[i] - 'A');
		else if ('a' <= ascii[i] && ascii[i] <= 'z')
			str[i] = L'a' + (ascii[i] - 'a');
		else {
			switch (ascii[i]) {
			case ' ':
				str[i] = L' ';
				break;
			case '-':
				str[i] = L'-';
				break;
			case '+':
				str[i] = L'+';
				break;
			case '*':
				str[i] = L'*';
				break;
			case '/':
				str[i] = L'/';
				break;
			case '&':
				str[i] = L'&';
				break;
			case '|':
				str[i] = L'|';
				break;
			case '%':
				str[i] = L'%';
				break;
			case '#':
				str[i] = L'#';
				break;
			case '!':
				str[i] = L'!';
				break;
			case '\r':
				str[i] = L'\r';
				break;
			case '\n':
				str[i] = L'\n';
				break;
			}
		}
	}

	str[i] = L'\0';
	return str;
}
