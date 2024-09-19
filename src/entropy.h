#ifndef _ENTROPY_H

#if !defined(_PARSER_H)
#include "parser.h"
#endif 

#define MAX_SIZE 256

typedef struct {
    unsigned char array[MAX_SIZE];
    unsigned int value[MAX_SIZE];
} SimpleHashTable;


typedef struct {
    char* buffer;
    int   start_pos;
    int   end_pos;
}DataBlock;


size_t 
len(const char* s){
    const char* p = s;
    while(*p) ++p;
    return p-s;
}

void 
set_datablock(DataBlock* db, char* buffer, int length){
    int i=0;
    // int sz = sizeof(buffer)/ sizeof(buffer[0]);
    int sz = length;
    db->end_pos = sz;
    db->start_pos = 0;
    db->buffer = (char *) malloc(sz);
    while(i < sz ){
        db->buffer[i] = buffer[i];
        i++;
    }
}

void 
init_hashtable(SimpleHashTable* hashtable){
    for(int i=0; i< MAX_SIZE; i++){
        hashtable->array[i] = i;
        hashtable->value[i] = 0;
    }
}

void 
iterate_hashtable(SimpleHashTable* hashtable){
    for(int i=0; i<MAX_SIZE; i++){
        printf(" [%d : %2d ] ,", hashtable->array[i],  hashtable->value[i]);
    }
    printf("\n");
}

unsigned int
inc_the_val(unsigned int val) {
    return val + 1;
}


double
shannon_entropy(const char* buffer, int length) {
    double entropy_value = 0.0;
    unsigned char temp_value ;
    float prob = 0;
    SimpleHashTable* hashtable = (SimpleHashTable *) malloc(sizeof(SimpleHashTable));
    init_hashtable(hashtable);
    DataBlock* dblock = (DataBlock *) malloc(sizeof(DataBlock));
    int data_len = length;
    // printf("data len :: %d\n", data_len);
    set_datablock(dblock, (char*) buffer, length);
    while (dblock->start_pos != dblock->end_pos) {
        temp_value = (unsigned char) dblock->buffer[dblock->start_pos++];
        //* increments by sizeof(char)
        hashtable->value[temp_value] =  inc_the_val(hashtable->value[temp_value]);
    }
    // iterate_hashtable(hashtable);
    // E(x) = - p(x) * log2(p(x))
    for (int i = 0; i < MAX_SIZE; i++) {
        int val = hashtable->value[i];
        if (val != 0) {
            // prob  = (float_t) ( hashtable->value[i] / data_len);
            prob = (float)( val / (float) data_len);
            entropy_value -= ( prob * log2(prob));
        }
    }
    free(hashtable);
    free(dblock);
    return entropy_value;
}

#endif 