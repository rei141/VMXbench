#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <dirent.h>
#include <string.h>

#define MAX_KVM_INTEL 0xc7000
#define MAX_KVM 0x1b2000
uint8_t cov[MAX_KVM];
int main (void){
    // FILE * f = 
    DIR *dir;
    struct dirent *dp;
	char path[64] = "./";

	dir=opendir(path);
		FILE * result = fopen("result","w");
	for(dp=readdir(dir);dp!=NULL;dp=readdir(dir)){
		if(strcmp(dp->d_name, ".")==0 ||strcmp(dp->d_name, "..")==0 ){
			continue;
		}
		// printf("%s\n",dp->d_name);
		sprintf(path,"./%s",dp->d_name);
        FILE * f = fopen(path,"rb");
		if (f==NULL){
			printf("error");
			exit(1);
		}
		memset(cov,0,MAX_KVM);
        int n = fread(cov, sizeof(uint8_t), MAX_KVM, f);
		int c= 0 ;
		// printf("hello\n");
		for(int i = 0; i < MAX_KVM;i++){
			c += cov[i];
		}
		fprintf(result,"%s %d\n", dp->d_name, c);
	}
	fclose(result);
	closedir(dir);
	return 0;

    


}