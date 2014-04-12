/* convert odex to dex
 * Copyright (C) 2014  吴潍浠
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */   
#include<stdio.h>
#include<stdlib.h>
#include<stdint.h>
#include<sys/mman.h>
#include<sys/types.h>
#include<sys/stat.h>
#include<fcntl.h>
#include<unistd.h>
#include<string.h>
#define DEX_OPT_MAGIC   "dey\n"
#define DEX_MAGIC       "dex\n"
struct odex_header {
    uint8_t magic[8];
    uint32_t dex_off;
    uint32_t dex_len;
};
struct dex_header {
    uint8_t magic[8];
    uint8_t padding[24];
    uint32_t file_len;
};
int main(int argc, char **argv) {
    if(argc != 3) {
        printf("usage:%s <odex> <dex>\n", argv[0]);
        return 0;
    }
    int ret = -1;
    int odexFD = 0, dexFD = 0;
    size_t odexSize = 0, dexSize = 0;
    if((odexFD = open(argv[1], O_RDONLY)) == -1) {
        perror("open odex error");
        return -1;
    }
    if((dexFD = open(argv[2], O_RDWR|O_CREAT, 00660)) == -1) {
        perror("open dex error");
        close(odexFD);
        return -1;
    }
    struct stat Stat;
    if(fstat(odexFD, &Stat)) {
        perror("fstat odex error");
        goto cls;
    }
    odexSize = Stat.st_size;
    uint8_t *odexBuf = NULL, *dexBuf = NULL;
    if((odexBuf = mmap(NULL, odexSize, PROT_READ, MAP_SHARED, odexFD, 0)) == MAP_FAILED) {
        perror("mmap odex error");
        goto cls;
    }
    struct odex_header *odexH = (struct odex_header *)odexBuf;
    struct dex_header *dexH = (struct dex_header *)(odexBuf + odexH->dex_off);
    if(memcmp(odexH->magic, DEX_OPT_MAGIC, 4)) {
        printf("odex bad magic error\n");
        goto bail;
    }
    if(memcmp(dexH->magic, DEX_MAGIC, 4)) {
        printf("dex bad magic error\n");
        goto bail;
    }
    if(odexH->dex_len != dexH->file_len || (odexH->dex_len + 40) > odexSize) {
        printf("dex bad file len error\n");
        goto bail;
    }
    dexSize = odexH->dex_len;
    if(ftruncate(dexFD, dexSize)) {
        perror("ftruncate dex error");
        goto bail;
    }
    if((dexBuf = mmap(NULL, dexSize, PROT_READ|PROT_WRITE, MAP_SHARED, dexFD, 0)) == MAP_FAILED) {
        perror("mmap dex error");
        goto bail;
    }
    memcpy(dexBuf, odexBuf + odexH->dex_off, dexSize);
    ret = 0;
    munmap(dexBuf, dexSize);
bail:
    munmap(odexBuf, odexSize);
cls:
    close(odexFD);
    close(dexFD);
    return ret;
}
