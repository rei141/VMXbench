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
// #include <process.h>
#include <sys/mman.h>

/* Period parameters */  
#define MT_N 624
#define MT_M 397
#define MATRIX_A 0x9908b0dfUL   /* constant vector a */
#define UPPER_MASK 0x80000000UL /* most significant w-r bits */
#define LOWER_MASK 0x7fffffffUL /* least significant r bits */

static unsigned long mt[MT_N]; /* the array for the state vector  */
static int mti=MT_N+1; /* mti==MT_N+1 means mt[MT_N] is not initialized */

/* initializes mt[MT_N] with a seed */
void init_genrand(unsigned long s)
{
    mt[0]= s & 0xffffffffUL;
    for (mti=1; mti<MT_N; mti++) {
        mt[mti] = 
	    (1812433253UL * (mt[mti-1] ^ (mt[mti-1] >> 30)) + mti); 
        /* See Knuth TAOCP Vol2. 3rd Ed. P.106 for multiplier. */
        /* In the previous versions, MSBs of the seed affect   */
        /* only MSBs of the array mt[].                        */
        /* 2002/01/09 modified by Makoto Matsumoto             */
        mt[mti] &= 0xffffffffUL;
        /* for >32 bit machines */
    }
}

/* initialize by an array with array-length */
/* init_key is the array for initializing keys */
/* key_length is its length */
/* slight change for C++, 2004/2/26 */
void init_by_array(unsigned long init_key[], int key_length)
{
    int i, j, k;
    init_genrand(19650218UL);
    i=1; j=0;
    k = (MT_N>key_length ? MT_N : key_length);
    for (; k; k--) {
        mt[i] = (mt[i] ^ ((mt[i-1] ^ (mt[i-1] >> 30)) * 1664525UL))
          + init_key[j] + j; /* non linear */
        mt[i] &= 0xffffffffUL; /* for WORDSIZE > 32 machines */
        i++; j++;
        if (i>=MT_N) { mt[0] = mt[MT_N-1]; i=1; }
        if (j>=key_length) j=0;
    }
    for (k=MT_N-1; k; k--) {
        mt[i] = (mt[i] ^ ((mt[i-1] ^ (mt[i-1] >> 30)) * 1566083941UL))
          - i; /* non linear */
        mt[i] &= 0xffffffffUL; /* for WORDSIZE > 32 machines */
        i++;
        if (i>=MT_N) { mt[0] = mt[MT_N-1]; i=1; }
    }

    mt[0] = 0x80000000UL; /* MSB is 1; assuring non-zero initial array */ 
}

/* generates a random number on [0,0xffffffff]-interval */
unsigned long genrand_int32(void)
{
    unsigned long y;
    static unsigned long mag01[2]={0x0UL, MATRIX_A};
    /* mag01[x] = x * MATRIX_A  for x=0,1 */

    if (mti >= MT_N) { /* generate N words at one time */
        int kk;

        if (mti == MT_N+1)   /* if init_genrand() has not been called, */
            init_genrand(5489UL); /* a default initial seed is used */

        for (kk=0;kk<MT_N-MT_M;kk++) {
            y = (mt[kk]&UPPER_MASK)|(mt[kk+1]&LOWER_MASK);
            mt[kk] = mt[kk+MT_M] ^ (y >> 1) ^ mag01[y & 0x1UL];
        }
        for (;kk<MT_N-1;kk++) {
            y = (mt[kk]&UPPER_MASK)|(mt[kk+1]&LOWER_MASK);
            mt[kk] = mt[kk+(MT_M-MT_N)] ^ (y >> 1) ^ mag01[y & 0x1UL];
        }
        y = (mt[MT_N-1]&UPPER_MASK)|(mt[0]&LOWER_MASK);
        mt[MT_N-1] = mt[MT_M-1] ^ (y >> 1) ^ mag01[y & 0x1UL];

        mti = 0;
    }
  
    y = mt[mti++];

    /* Tempering */
    y ^= (y >> 11);
    y ^= (y << 7) & 0x9d2c5680UL;
    y ^= (y << 15) & 0xefc60000UL;
    y ^= (y >> 18);

    return y;
}

#define VMX_MSR_VMX_BASIC (rdmsr(0x480))
#define VMX_MSR_VMX_PINBASED_CTRLS (rdmsr(0x481))
#define VMX_MSR_VMX_TRUE_PINBASED_CTRLS (rdmsr(0x48d))
#define VMX_MSR_VMX_PROCBASED_CTRLS (rdmsr(0x482))
#define VMX_MSR_VMX_TRUE_PROCBASED_CTRLS (rdmsr(0x48e))
#define VMX_MSR_VMX_VMEXIT_CTRLS (rdmsr(0x483))
#define VMX_MSR_VMX_TRUE_VMEXIT_CTRLS (rdmsr(0x48f))
#define VMX_MSR_VMX_VMENTRY_CTRLS (rdmsr(0x484))
#define VMX_MSR_VMX_TRUE_VMENTRY_CTRLS (rdmsr(0x490))
#define VMX_MSR_MISC (rdmsr(0x485))
#define VMX_MSR_CR0_FIXED0 (rdmsr(0x486))
// allowed 1-setting in CR0 in VMX mode
#define VMX_MSR_CR0_FIXED1 (rdmsr(0x487))
// bit VMXE(13) required to be set in CR4 to enter VMX mode
#define VMX_MSR_CR4_FIXED0 (rdmsr(0x488))
// allowed 1-setting in CR0 in VMX mode
#define VMX_MSR_CR4_FIXED1 (rdmsr(0x489))
#define VMX_MSR_VMX_PROCBASED_CTRLS2 (rdmsr(0x48b))
#define VMX_MSR_VMX_EPT_VPID_CAP (rdmsr(0x48c))

static inline uint64_t rdmsr(uint32_t index)
{
    uint32_t eax, edx;
    asm volatile ("rdmsr"
		  : "=a" (eax), "=d" (edx)
		  : "c" (index));
    return ((uint64_t)edx << 32) | eax;
}

int main(int argc, char** argv) {
    for(uint32_t i = 0; i < 16; i++){
        uint64_t ans = rdmsr(0x480+i);
        printf("0x%x : 0x%lx\n", 0x480+i,ans);
    }
    return 0;
}