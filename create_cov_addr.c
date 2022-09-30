#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <dirent.h>
#include <string.h>
uint8_t cov[0xae000];
int main (int argc, char * argv[]){
    // FILE * f = 
    // DIR *dir;
    // struct dirent *dp;
	char path[64] = "cov_";

	// dir=opendir(path);
    char a[64];
    int b = 0;
    // printf("%d",sizeof(argv[1]));
    for (int i = 0; i<100; i++){
        printf("%c\n",argv[1][i]);
        if (argv[1][i] == 'n'){
            b = i;
            break;
        }
    }
    sprintf(a,"cov_%s",argv[1]+b);
	FILE * result = fopen(a,"w");
    // FILE *
	// for(dp=readdir(dir);dp!=NULL;dp=readdir(dir)){
	// 	if(strcmp(dp->d_name, ".")==0 ||strcmp(dp->d_name, "..")==0 ){
	// 		continue;
	// 	}
		// printf("%s\n",dp->d_name);
		sprintf(path,"%s",argv[1]);
        printf("%s\n",argv[1]+b);
        FILE * f = fopen(path,"rb");
		if (f==NULL){
			printf("error");
			exit(1);
		}
		
        int n = fread(cov, sizeof(uint8_t), 0xae000, f);
		int c= 0 ;
		// printf("hello\n");
		for(int i = 0; i < 0xae000;i++){
			// c += cov[i];
            if (cov[i] == 1)
		    fprintf(result,"%x\n",i);
		}
	
    fclose(f);
	fclose(result);
	// closedir(dir);
	return 0;

    


}