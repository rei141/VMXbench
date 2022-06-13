#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <dirent.h>
#include <string.h>
uint8_t cov[0x60000];
int main (void){
    // FILE * f = 
    DIR *dir;
    struct dirent *dp;
	char path[64] = "./record/";

	dir=opendir(path);
		FILE * result = fopen("result","w");
	for(dp=readdir(dir);dp!=NULL;dp=readdir(dir)){
		if(strcmp(dp->d_name, ".")==0 ||strcmp(dp->d_name, "..")==0 ){
			continue;
		}
		printf("%s\n",dp->d_name);
		sprintf(path,"./record/%s",dp->d_name);
        FILE * f = fopen(path,"rb");
		if (f==NULL){
			printf("error");
			exit(1);
		}
		
        int n = fread(cov, sizeof(uint8_t), 0x60000, f);
		int c= 0 ;
		printf("hello\n");
		for(int i = 0; i < 0x60000;i++){
			c += cov[i];
		}
		fprintf(result,"%s %d\n", dp->d_name, c);
	}
	fclose(result);
	closedir(dir);
	return 0;

    


}