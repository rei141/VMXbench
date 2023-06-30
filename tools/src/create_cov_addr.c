#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <dirent.h>
#include <string.h>
#include <libgen.h>
#include "fuzz.h"

int main (int argc, char * argv[]){
    check_cpu_vendor();

	uint8_t *cov = malloc(MAX_KVM);
    char* filePath = strdup(argv[1]);
    char* dirPath = strdup(argv[1]); 

    char* base = basename(filePath);
    char* dir = dirname(dirPath);

    char output[256];  // Buffer for the output file name

    snprintf(output, sizeof(output), "%s/cov_%s", dir, base);

    FILE * input_fp = fopen(argv[1],"rb");
	if (input_fp == NULL) {
		fprintf(stderr, "fopen failed\n");
		return 1;
	}

    FILE * output_fp = fopen(output,"w");
	if (output_fp == NULL) {
		fprintf(stderr, "fopen failed\n");
		return 1;
	}
	
	int n = fread(cov, sizeof(uint8_t), MAX_KVM, input_fp);
	for(int i = 0; i < n;i++){
		if (cov[i] == 1)
		fprintf(output_fp, "%x\n", i);
	}
	
    fclose(input_fp);
	fclose(output_fp);
	printf("%s\n", output);
	return 0;
}