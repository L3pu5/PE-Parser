#include <stdio.h>
#include <windows.h>

#include "./colours.h"


typedef struct _BASE_RELOCATION_ENTRY { 
    WORD Type   : 4;
    WORD Offset : 12;
} BASE_RELOCATION_ENTRY, *PBASE_RELOCATION_ENTRY;

void usage() {
    printf(COLOUR_GREEN);
    printf("Usage: \n");
    printf(COLOUR_RESET);
}

static void printBanner(){
    printf(COLOUR_MAGENTA);
    printf("----------------------------------------------------------------------------------------------\n");
    printf(COLOUR_RESET);
}

int main () {
    //Let's open a test application, such as ourselves and parse the PE headers.
    printBanner();
    printf(COLOUR_MAGENTA);


    FILE* hFile = fopen("C:\\Windows\\System32\\calc.exe", "r");
    fseek(hFile, 0, SEEK_END);
    unsigned long fileLength = ftell(hFile);
    fseek(hFile, 0, SEEK_SET);
    char* fBuffer = malloc(fileLength);
    fread(fBuffer, 1, fileLength, hFile);
    printf("FILE LENGTH: %lu\n", fileLength);
    fclose(hFile);
    IMAGE_DOS_HEADER* DosHeader = (IMAGE_DOS_HEADER*) fBuffer;
    printf(COLOUR_RESET);
    printf("DOS HEADER\n");
    printf("SIG: ");

    if(DosHeader->e_magic == IMAGE_DOS_SIGNATURE){
        printf(COLOUR_BG_GREEN);
        printf("PASSED");
        printf(COLOUR_RESET);
    }
    else{
        printf(COLOUR_BG_RED);
        printf("FAILED");
        printf(COLOUR_RESET);
        printf("Are you sure this is an executable?\n");
        free(fBuffer);
        exit(1);
    }   


    printf(" | ");
    printf("e_lfanew: 0x%x", DosHeader->e_lfanew);
    printf("\nNT HEADER\nSIG: ");
    
    PIMAGE_NT_HEADERS32 NTHeader = (PIMAGE_NT_HEADERS32) ((fBuffer + ((PIMAGE_DOS_HEADER)fBuffer)->e_lfanew) - 1);  


    if(NTHeader->Signature == IMAGE_NT_SIGNATURE){
        printf(COLOUR_BG_GREEN);
        printf("PASSED");
        printf(COLOUR_RESET);
    }
    else{
        printf(COLOUR_BG_RED);
        printf("FAILED");
        printf(COLOUR_RESET);
        printf("Are you sure this is an executable?\n");
        free(fBuffer);
        exit(1);
    }   

    printf("\n----------------------------------------------------------------------------------------------");
    
    IMAGE_OPTIONAL_HEADER32 OPTHeader = (IMAGE_OPTIONAL_HEADER32) NTHeader->OptionalHeader;
    printf("\nOPT HEADER\nSIG: ");
    if(OPTHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC ){
        printf(COLOUR_BG_GREEN);
        printf("EXE32");
        printf(COLOUR_RESET);
    } else if (OPTHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)  {
        printf(COLOUR_BG_GREEN);
        printf("EXE64");
        printf(COLOUR_RESET);
    }
    else{
        printf(COLOUR_BG_RED);
        printf("FAILED");
        printf(COLOUR_RESET);
        printf("Are you sure this is an executable?\n");
        free(fBuffer);
        exit(1);
    }  
    printf("\n");
    printf("ImageBase(First Byte Preferred):   0x%x\n", OPTHeader.BaseOfCode);
    printf("BaseOfCode(RVA):                   0x%x\n", OPTHeader.BaseOfCode);
    printf("BaseOfData(RVA):                   0x%x\n", OPTHeader.BaseOfData);
    printf("NumberOfRvaAndSizes:               0d%u\n", OPTHeader.NumberOfRvaAndSizes);
    printf("Major Image Version:               0x%x\n", OPTHeader.MajorImageVersion);
    printf("SIZE OF IMAGE:                     0d%lu", OPTHeader.SizeOfImage);
    printf("\n----------------------------------------------------------------------------------------------\n");

    printf("IMAGE_DATA_DIRECTORY\n");


    for (size_t i = 0; i < 16; i++)
    {
        printf("IMAGE_DATA_DIRECTORY [ %d ]\n", i);
        printf("Size: 0x%x\n", NTHeader->OptionalHeader.DataDirectory[i].Size);
        printf("RVA : 0x%x\n", NTHeader->OptionalHeader.DataDirectory[i].VirtualAddress);
        printf("--\n");
    }

    printf("\n----------------------------------------------------------------------------------------------\n");

    printf("SECTIONS\n");
    printf("NUMBER OF SECTIONS: %lu\n", NTHeader->FileHeader.NumberOfSections );
    printf("NUMBER OF SYMBOLS : %lu\n", NTHeader->FileHeader.NumberOfSymbols );
    printf("----------------------------------------------------------------------------------------------\n");
    
    PIMAGE_SECTION_HEADER SecHeader = IMAGE_FIRST_SECTION(NTHeader);
    for (size_t i = 0; i < NTHeader->FileHeader.NumberOfSections; i++)
    {
        printf("SECTION HEADER %d\n", i);
        printf("Name            :        %.8s\n", SecHeader[i].Name);
        printf("Virtual Address :        0x%d\n", SecHeader[i].VirtualAddress);
        printf("Ptr to Raw Data :        0x%d\n", SecHeader[i].PointerToRawData);
        printf("Size of Raw Data:        0x%d\n", SecHeader[i].SizeOfRawData);
        printf("--\n");
    }
    
    printf("\n----------------------------------------------------------------------------------------------\n");

    free(fBuffer);
    printBanner();

    return 0;
}