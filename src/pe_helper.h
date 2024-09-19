#ifndef PE_HELPER_H
#define PE_HELPER_H

#if !(defined(_PARSER_H))
#include "parser.h"
#endif 


typedef unsigned char           u8;
typedef unsigned short          u16;
typedef unsigned int            u32;
typedef unsigned long long int  u64;

#define stringify(x) #x
#define global static
// #define ABS(x, y) (((x - y) > 0) ? (u64) (x-y) : (u64) (-1 * (x -y)))

#define abs(x, y) (((x-y) < 0) ? (y-x) : (x-y))

#define swapShortEndian(x) ((((x >> 0) << 8) & 0xff00) |( ((x >> 8) << 0) & 0x00ff))

static inline u32 swapEndianess(u32 x){ return ( (x >> 24) & 0x000000ff | (x >> 8)  & 0x0000ff00 | (x << 8)  & 0x00ff0000 |(x << 24) & 0xff000000); }

static inline u8 readLittleInt8(FILE* fp){ return (u8) ( fgetc(fp)); }

static inline u16 readLittleInt16(FILE* fp){ return (((u16)fgetc(fp)) | ((u16)fgetc(fp) << 8) ); }

static inline u32 readLittleInt32(FILE* fp) { return (u32) fgetc(fp) | ((u64) fgetc(fp) << 8) | ((u64) fgetc(fp) << 16) | ((u64) fgetc(fp) << 24);}


static inline u64 readLittleInt64(FILE* fp) { return (u64) fgetc(fp) | ((u64) fgetc(fp) << 8) | ((u64) fgetc(fp) << 16) | ((u64) fgetc(fp) << 24) | ((u64) fgetc(fp) << 32) | ((u64) fgetc(fp) << 40) | ((u64) fgetc(fp) << 48) | ((u64) fgetc(fp) << 56);}

static int 
length(char* x){
    int count=0;
    for(int i=0; i; i++){
        if (*(x+i) =='\x00') break;
        else count++;
    }
    return count;
}

static inline void
skip( FILE* fp, size_t size){
    fseek(fp, ftell(fp) + size, SEEK_SET);
}

static inline 
void print_mem(char* name, u64 value){
    printf("|%-50s  |  0x%-10x|\n", name, value);
    fflush(stdout);
}

static inline 
void print_str(char* name, char* value){
    printf("|%-50s  |  %-12s|\n", name, value);
    fflush(stdout);
}
static inline 
void print_mem_fmt(char* name, u64 value){
    printf("|%-50s  |  0x%-10x|\n\t\t", name, value);
    fflush(stdout);
}
#endif