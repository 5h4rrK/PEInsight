# PEInsight

**PEInsight** is a tool designed to parse and inspect the structure of Portable Executable (PE) files, written in C. The Portable Executable format is the file format for executables, object code, DLLs, and others used in 32-bit and 64-bit versions of Windows operating systems. PEInsight provides a detailed breakdown of the internal structure of PE files

## Features

PEInsight currently parses and extracts information from the following structures in PE files:

- [X] **DOS Header** (`DOS_HEADER`)  
  
- [X] **DOS Stub** (`DOS_STUB`)  

- [X] **NT Headers** (`NT_HEADERS`)  

- [X] **Section Headers** (`SECTION_HEADERS`)  

- [X] **Sections Data Dumping** (`SECTIONS_DATA_DUMPING`)  

- [X] **Import Descriptors**  

## To-do

- [ ] **Entropy Calculation for Sections**  

## Usage
```bash
    gcc main.c -o parser -lm
```
