#include "src/parser.c"

int main(int argc, char** argv[]){
    // FILE* fp = fopen("../../assests/main.exe","r");
    if (argc < 2) {fprintf(stderr, "Requires filename\n\t ./parser <exe-file>\n");exit(0xff);}
    FILE* fp = fopen((char *) argv[1],"r");
    if (fp == NULL){ printf("Failed to read file\n");}
    printf("File Read Successfully\n");
    parse_structure(fp);
    fclose(fp);
    traverse_link(head);

}
