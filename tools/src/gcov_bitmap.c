#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <ctype.h>
#define BITMAP_SIZE 65536 // 64kB

int ind;

int process_gcov_file(const char *filename, uint8_t *bitmap) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        perror("fopen");
        return 0;
    }

    char line[256];
    while (fgets(line, sizeof(line), file)) {
        char *colon_ptr = strchr(line, ':');
        if (!colon_ptr) continue; // ":"がない場合、この行を無視
        if(colon_ptr[-1] == '-'){
            continue;
        }
        // ":"より左の部分を抽出
        char left_part[256];
        strncpy(left_part, line, colon_ptr - line);
        left_part[colon_ptr - line] = '\0';
        // 左部分が"#####"かどうかをチェック
        if (strstr(left_part, "#")) {
            printf("%d Line not covered\n",ind);
            ind += 1;
            continue;
        }

        // 左部分から数字を抽出
        char *ptr = left_part;
        while (*ptr && isspace((unsigned char)*ptr)) ptr++; // 空白をスキップ
        // printf("%s ", ptr);
        if (*ptr) {
            char *end_ptr;
            long count = strtol(ptr, &end_ptr, 10); // 数字を解析
            if (*end_ptr == '*') end_ptr++; // "*"をスキップ
            if (*end_ptr == '\0') {
                if (count >= 128)
                    bitmap[ind] |= 0x80;
                else if (count >= 32)
                    bitmap[ind] |= 0x40;
                else if (count >= 16)
                    bitmap[ind] |= 0x20;
                else if (count >= 8)
                    bitmap[ind] |= 0x10;
                else if (count >= 4)
                    bitmap[ind] |= 0x08;
                else if (count >= 3)
                    bitmap[ind] |= 0x04;
                else if (count >= 2)
                    bitmap[ind] |= 0x02;
                else if (count >= 1)
                    bitmap[ind] |= 0x01;
                printf("byte #%d = 0x%x\n", ind, bitmap[ind]);
                ind += 1;
            }
        }
        if (ind >= BITMAP_SIZE){
            printf("index reached BITMAP_SIZE with %s", filename);
            return -1;
        }
    }

    fclose(file);
    return 0;
}

int compare(const void *a, const void *b) {
    return strcmp(*(const char **)a, *(const char **)b);
}

int main(int argc, char *argv[]) {
    uint8_t bitmap[BITMAP_SIZE] = {0};

    DIR *dir = opendir(".");
    if (!dir) {
        perror("opendir");
        return 1;
    }
    
    char **filenames = NULL;
    size_t count = 0;
    struct dirent *entry;
    while ((entry = readdir(dir))) {
        if (strstr(entry->d_name, ".gcov")) {
            filenames = realloc(filenames, (count + 1) * sizeof(*filenames));
            if (filenames == NULL) {
                perror("realloc");
                return 1;
            }
            filenames[count] = strdup(entry->d_name);
            if (filenames[count] == NULL) {
                perror("strdup");
                return 1;
            }
            count++;
        }
    }
    closedir(dir);

    qsort(filenames, count, sizeof(*filenames), compare);
    for (size_t i = 0; i < count; i++) {
        printf("%s\n", filenames[i]);
        if (process_gcov_file(filenames[i], bitmap) == -1)
            return -1;
        free(filenames[i]);
    }
    free(filenames);

    FILE *file = fopen(argv[1], "wb");
    if (!file) {
        perror("fopen");
        return 1;
    }
    fwrite(bitmap, BITMAP_SIZE, sizeof(uint8_t), file);
    fclose(file);

    return 0;
}