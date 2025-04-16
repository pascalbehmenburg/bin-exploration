Collection of binary exploration and other topics.

Starting with implementing and understanding concepts of:

Tool Interface Standard (TIS)
Portable Formats Specification
Version 1.1

as can be read here: https://refspecs.linuxfoundation.org/elf/TIS1.1.pdf

Roadmap:

- [x] parse elf headers from binary files
- [ ] Parse ELF section headers and their attributes
- [ ] Implement string table parsing for section and symbol names
- [ ] Parse symbol tables to extract symbol information
- [ ] Handle relocation entries for linking and loading
- [ ] Implement program header parsing for executable segments
- [ ] Support program loading simulation from ELF to memory
- [ ] Understand dynamic linking resolution for shared libraries
- [ ] Understand C library interactions with ELF binaries
- [ ] understanding dwarf
