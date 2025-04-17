import struct
from dataclasses import dataclass, field, fields, is_dataclass
from enum import Enum, IntFlag
from typing import BinaryIO

# _____________________________________________________________
# Elf32_Addr 4 4 Unsigned program address
# Elf32_Half 2 2 Unsigned medium integer
# Elf32_Off 4 4 Unsigned file offset
# Elf32_Sword 4 4 Signed large integer
# Elf32_Word 4 4 Unsigned large integer
# unsigned char 1 1 Unsigned small integer
# __________________________________________________________


def _pretty(obj, indent=0):
    sp = " " * 8
    indent_str = sp * indent
    # Dataclass → recurse
    if is_dataclass(obj):
        cls_name = obj.__class__.__name__
        out = [f"{indent_str}{cls_name}("]
        for idx, f in enumerate(fields(obj)):
            # skip hidden fields
            if f.metadata.get("redacted", False):
                continue
            val = getattr(obj, f.name)
            # First field of top‐level ElfHeader: no "e_ident="
            if indent == 0 and idx == 0 and is_dataclass(val):
                nested = _pretty(val, indent + 1)
                out.append(f"{nested}, ")
            else:
                val_repr = _pretty(val, indent + 1)
                out.append(f"{sp * (indent + 1)}{f.name}={val_repr},")
        out.append(f"{indent_str})")
        return "\n".join(out)
    # Enum → qualified name
    if isinstance(obj, Enum):
        return f"{obj.__class__.__name__}.{obj.name}"
    # bytes → repr
    if isinstance(obj, (bytes, bytearray)):
        return repr(obj)
    # int → hex
    if isinstance(obj, int):
        return hex(obj)
    # fallback
    return repr(obj)


class ElfDataEncoding(Enum):
    """Data encoding format for ELF files."""

    ELFDATANONE = 0
    """Invalid data encoding."""

    ELFDATA2LSB = 1
    """Little endian encoding."""

    ELFDATA2MSB = 2
    """Big endian encoding."""

    def __repr__(self):
        return f"{self.name}[{self.value}]"


class ElfFileType(Enum):
    """File type for ELF files.

    Name        Value       Mapping
    ET_NONE     0           No file type
    ET_REL      1           Relocatable file
    ET_EXEC     2           Executable file
    ET_DYN      3           Shared object file
    ET_CORE     4           Core file
    ET_LOPROC   0xff00      Processor-specific
    ET_HIPROC   0xffff      Processor-specific
    """

    ET_NONE = 0
    """No file type."""

    ET_REL = 1
    """Relocatable file."""

    ET_EXEC = 2
    """Executable file."""

    ET_DYN = 3
    """Shared object file."""

    ET_CORE = 4
    """Core file."""

    ET_LOPROC = 0xFF00
    """Processor-specific."""

    ET_HIPROC = 0xFFFF
    """Processor-specific."""

    def __repr__(self):
        return f"{self.name}[{self.value}]"


class ElfVersion(Enum):
    """Version of the ELF file.

    Name        Value       Meaning
    EV_NONE     0           Invalid version
    EV_CURRENT  1           Current version
    """

    EV_NONE = 0
    """Invalid version."""

    EV_CURRENT = 1
    """Current version."""

    def __repr__(self):
        return f"{self.name}[{self.value}]"


class ElfMachine(Enum):
    """Machine type for ELF files.

    Name        Value       Meaning
    EM_NONE     0           No machine
    EM_M32      1           AT&T WE 32100
    EM_SPARC    2           SPARC
    ..
    EM_X86_64   62          AMD x86-64 architecture


    Refer to `/usr/include/elf.h` or run something like:
    ```bash
    cat /usr/include/elf.h | grep -n -A190 "EM_NONE"
    ```
    to see all (locally) available machine codes as of today.
    """

    EM_NONE = 0
    """No machine."""

    EM_M32 = 1
    """AT&T WE 32100."""

    EM_SPARC = 2
    """SPARC."""

    EM_AMD_X86_64 = 62
    """AMD x86-64 architecture."""

    # Add more machine types as needed

    def __repr__(self):
        return f"{self.name}[{self.value}]"


class ElfFileClass(Enum):
    """Class type for ELF files."""

    ELFCLASSNONE = 0
    """Invalid class."""

    ELFCLASS32 = 1
    """32-bit class."""

    ELFCLASS64 = 2
    """64-bit class."""

    def __repr__(self):
        return f"{self.name}[{self.value}]"


@dataclass
class ElfIdentifier[E: ElfDataEncoding]:
    """Marks the file as an object file and provides machine-independent
    data with which to decode and interpret the file-contents. (16 bytes)

    e_ident[] Identification Indexes:
    Name        Value       Purpose                     Accessed bytes
    EI_MAG0     0           File identification         0x7f
    EI_MAG1     1           File identification         'E'
    EI_MAG2     2           File identification         'L'
    EI_MAG3     3           File identification         'F'
    EI_CLASS    4           File class (32/64 bit)      0/1/2 -> ELFCLASSNONE/ELFCLASS32/ELFCLASS64
    EI_DATA     5           Data encoding               0/1/2 -> ELFDATANONE/ELFDATA2LSB/ELFDATA2MSB
    EI_VERSION  6           File version                1     -> EV_CURRENT
    EI_PAD      7           Start of padding bytes      reserved fields default to zero
    """

    magic: bytes
    """Magic number identifying the file as an ELF file. (4 bytes)"""

    file_class: ElfFileClass
    """Class type of the ELF file. (1 byte)"""

    data_encoding: E
    """Data encoding format (Endianness) of the ELF file. (1 byte)"""

    version: ElfVersion
    """Version of the ELF file. (1 byte)"""

    def __repr__(self):
        return _pretty(self)

    @classmethod
    def from_bytes(cls, e_ident: bytes) -> "ElfIdentifier[ElfDataEncoding]":
        """Creates an ElfIdentifier instance from bytes."""
        if len(e_ident) != 16:
            raise ValueError("Invalid e_ident length.")

        if (magic := e_ident[0:4]) != b"\x7fELF":
            raise ValueError("Magic number invalid. Not an ELF file.")

        if not (file_class := ElfFileClass(e_ident[4])):
            raise ValueError(f"Invalid class type: {file_class}")

        if not (data_encoding := ElfDataEncoding(e_ident[5])):
            raise ValueError(f"Invalid data encoding: {data_encoding}")

        if not (version := ElfVersion(e_ident[6])):
            raise ValueError(f"Invalid version: {version}")

        return cls(
            magic=magic,
            file_class=file_class,
            data_encoding=data_encoding,
            version=version,
        )


class ElfSectionHeaderOffsets(Enum):
    """Section header offsets for ELF files."""

    SHN_UNDEF = 0
    """Undefined section."""

    SHN_LORESERVE = 0xFF00
    """This value specifies the lower bound of the range of reserved indexes."""

    SHN_LOPROC = 0xFF00
    """Values in the range (`SHN_LOPROC` through `SHN_HIPROC` incl.) 
    are reserved for processor-specific semantics.
    """

    SHN_HIPROC = 0xFF1F
    """Values in the range (`SHN_LOPROC` through `SHN_HIPROC` incl.) 
    are reserved for processor-specific semantics.
    """

    SHN_ABS = 0xFFF1
    """Absolute values for the corresponding reference. For example,
    symbols defined relative to section number SHN_ABS have absolute values and are
    not affected by relocation.
    """

    SHN_COMMON = 0xFFF2
    """Symbols defined relative to this section are common symbols, such as FORTRAN
    COMMON or unallocated C external variables.
    """

    SHN_HIRESERVE = 0xFFFF
    """The upper bound of the range of reserved indexes. The system
    reserves indexes between `SHN_LORESERVE` and `SHN_HIRESERVE`, inclusive; the
    values do not reference the section header table. That is, the section header table
    does not contain entries for the reserved indexes.
    """


class SectionHeaderType(Enum):
    """A section header's sh_type member specifies the section's semantics.

    Name            Value
    SHT_NULL        0
    SHT_PROGBITS    1
    SHT_SYMTAB      2
    SHT_STRTAB      3
    SHT_RELA        4
    SHT_HASH        5
    SHT_DYNAMIC     6
    SHT_NOTE        7
    SHT_NOBITS      8
    SHT_REL         9
    SHT_SHLIB       10
    SHT_DYNSYM      11
    SHT_LOPROC      0x70000000
    SHT_HIPROC      0x7fffffff
    SHT_LOUSER      0x80000000
    SHT_HIUSER      0xffffffff
    """

    SHT_NULL = 0
    """This value marks the section header as inactive; it does not have an associated section.
    Other members of the section header have undefined values.
    """

    SHT_PROGBITS = 1
    """The section holds information defined by the program, whose format and meaning are
    determined solely by the program."""

    # These sections hold a symbol table. Currently, an object file may have only one sec-
    # tion of each type, but this restriction may be relaxed in the future. Typically,
    # SHT_SYMTAB provides symbols for link editing, though it may also be used for
    # dynamic linking. As a complete symbol table, it may contain many symbols unneces-
    # sary for dynamic linking. Consequently, an object file may also contain a
    # SHT_DYNSYM section, which holds a minimal set of dynamic linking symbols, to save
    # space. See ‘‘Symbol Table’’ below for details.

    SHT_SYMTAB = 2
    """Typically, `SHT_SYMTAB` provides symbols for link editing, though it may also be used for
    dynamic linking. As a complete symbol table, it may contain many symbols unneces-
    sary for dynamic linking. 
    """

    SHT_STRTAB = 3
    """The section holds a string table. An object file may have multiple string table sections.
    See "String Table" below for details.
    """

    SHT_RELA = 4
    """The section holds relocation entries with explicit addends, such as type Elf32_Rela
    for the 32-bit class of object files. An object file may have multiple relocation sections.
    See "Relocation" below for details.
    """

    SHT_HASH = 5
    """The section holds a symbol hash table. All objects participating in dynamic linking
    must contain a symbol hash table. Currently, an object file may have only one hash
    table, but this restriction may be relaxed in the future. See "Hash Table" in Part 2 for
    details."""

    SHT_DYNAMIC = 6
    """The section holds information for dynamic linking. Currently, an object file may have
    only one dynamic section, but this restriction may be relaxed in the future. See
    "Dynamic Section" in Part 2 for details.
    """

    SHT_NOTE = 7
    """The section holds information that marks the file in some way.

    See "Note Section" in Part 2 for details.
    """

    SHT_NOBITS = 8
    """A section of this type occupies no space in the file but otherwise resembles
    `SHT_PROGBITS`. Although this section contains no bytes, the `sh_offset` member
    contains the conceptual file offset.
    """

    SHT_REL = 9
    """The section holds relocation entries without explicit addends, such as type
    Elf32_Rel for the 32-bit class of object files. An object file may have multiple reloca-
    tion sections.

    See "Relocation" below for details.
    """

    SHT_SHLIB = 10
    """This section type is reserved but has unspecified semantics. Programs that contain a
    section of this type do not conform to the ABI.
    """

    SHT_DYNSYM = 11
    """Consequently, an object file may also contain a `SHT_DYNSYM` section, 
    which holds a minimal set of dynamic linking symbols, to save space.
    See "Symbol Table" below for details.
    """

    SHT_LOPROC = 0x70000000
    """Values in this inclusive range (`SHT_LOPROC` through `SHT_HIPROC` incl.) are 
    reserved for processor-specific semantics.
    """

    SHT_HIPROC = 0x7FFFFFFF
    """Values in this inclusive range (`SHT_LOPROC` through `SHT_HIPROC` incl.) are 
    reserved for processor-specific semantics.
    """

    SHT_LOUSER = 0x80000000
    """This value specifies the lower bound of the range of indexes reserved for application
    programs.
    """

    SHT_HIUSER = 0xFFFFFFFF
    """This value specifies the upper bound of the range of indexes reserved for application
    programs. Section types between `SHT_LOUSER` and `SHT_HIUSER` may be used by
    the application, without conflicting with current or future system-defined section
    types.
    """


class SectionHeaderFlags(IntFlag):
    """Section header flags for ELF files."""

    SHF_WRITE = 0x1
    """The section contains writable data."""

    SHF_ALLOC = 0x2
    """The section occupies memory during process execution."""

    SHF_EXECINSTR = 0x4
    """The section contains executable instructions."""

    SHF_MASKPROC = 0xF0000000
    """The bits of the sh_flags member are reserved for processor-specific semantics."""


@dataclass
class ElfHeader[E: ElfDataEncoding]:
    """Representation of the executable and link format (ELF).

    Ref.: https://refspecs.linuxfoundation.org/elf/TIS1.1.pdf

    Example:
    ```py
    with open(filepath, 'rb') as f:
        elf_header = ElfHeader.from_file(f)
    ```
    """

    e_ident: ElfIdentifier[E]
    """Marks the file as an object file and provides machine-independent
    data with which to decode and interpret the file-contents. (16 bytes)
    """

    e_type: ElfFileType
    """Identifies the object file type. (2 bytes)
    File contents are unspecified but ET_CORE is reserved to mark the file.
    Values from ET_LOPROC through ET_HIPROC (incl.) are reserved for processor-specific semantics. 
    """

    e_machine: ElfMachine
    """Specifies the required architecture for an individual file. (2 bytes)"""

    e_version: ElfVersion
    """Identifies the object file version. (4 bytes)
    Value 1 signifies the original file format which persists to this day.
    """

    e_entry: int
    """Gives the virtual address to which the system first transfers control,
    thus starting the process. If the file has no associated entry point, this member holds zero.
    (4/8 bytes depending on 32/64-bit)
    """

    e_phoff: int
    """Describes the `program` header table's file offset in bytes. (4/8 bytes≤)
    If the file has no `program` header table, this member holds zero.
    """

    e_shoff: int
    """Describes the `section` header table's file offset in bytes. (4/8 bytes)
    If the file has no `section` header table, this member holds zero.
    """

    e_flags: int
    """Holds processor-specific flags associated with the file. (4 bytes)
    Flag names take the form EF_<machine_flag>.
    TODO: See "Machine information"
    """

    e_ehsize: int
    """Holds the ELF header's size in bytes. (2 bytes)"""

    e_phentsize: int
    """Holds the size in bytes of one entry in the file's program header table. (2 bytes)
    All entries are the same size.
    """

    e_phnum: int
    """Holds the number of entries in the program header table. (2 bytes)
    Thus the product of `e_phentsize` and `e_phnum` give the table's size in bytes. 
    If a file has no program header table, `e_phnum` holds the value zero.
    """

    e_shentsize: int
    """Holds a section header's size in bytes. (2 bytes)
    A section header is one entry in the section header table; all entries are the same size"""

    e_shnum: int
    """The number of entries in the section header table. (2 bytes)
    Thus the product of `e_shentsize` and `e_shnum` gives the section header table's size in bytes. If a file
    has no section header table, `e_shnum` holds the value zero.
    """

    e_shstrndx: int
    """The section header table index of the entry associated with the 
    section name string table. If the file has no section name string table, 
    this member holds the value `SHN_UNDEF`. (2 bytes)
    TODO: See Sections and String Table below for more information
    """

    file_copy: bytes = field(metadata={"redacted": True})
    """Copy of the file contents from which the ELF header was read."""

    def __repr__(self):
        return _pretty(self)

    @classmethod
    def from_file(cls, file: BinaryIO) -> "ElfHeader[ElfDataEncoding]":
        """Parses an ELF header from a file handle."""
        # read once
        file_copy = file.read()

        try:
            e_ident = ElfIdentifier.from_bytes(file_copy[0:16])
        except ValueError as e:
            raise ValueError(f"Invalid ELF identifier: {e}")

        endianness_fmt = (
            ">" if e_ident.data_encoding == ElfDataEncoding.ELFDATA2MSB else "<"
        )
        is_64bit = e_ident.file_class == ElfFileClass.ELFCLASS64

        # Describe binary format for struct.unpack
        bin_fmt = (
            f"{endianness_fmt}"  # Endianness
            + "HH"  # e_type, e_machine
            + "I"  # e_version
            + f"{'Q' if is_64bit else 'I'}" * 3  # e_entry, e_phoff, e_shoff
            + "I"  # e_flags
            + "HHHHHH"  # e_ehsize through e_shstrndx
        )

        # unpack only the bytes immediately after the 16‑byte e_ident
        header_size = struct.calcsize(bin_fmt)
        header_data = struct.unpack(bin_fmt, file_copy[16 : 16 + header_size])

        return cls(
            e_ident=e_ident,
            e_type=ElfFileType(header_data[0]),
            e_machine=ElfMachine(header_data[1]),
            e_version=ElfVersion(header_data[2]),
            e_entry=header_data[3],
            e_phoff=header_data[4],
            e_shoff=header_data[5],
            e_flags=header_data[6],
            e_ehsize=header_data[7],
            e_phentsize=header_data[8],
            e_phnum=header_data[9],
            e_shentsize=header_data[10],
            e_shnum=header_data[11],
            e_shstrndx=header_data[12],
            # preserve the full file bytes
            file_copy=file_copy,
        )

    def get_section_header_table(self):
        """Returns the section header table."""
        for i in range(self.e_shnum):
            offset = self.e_shoff + i * self.e_shentsize
            elf_section = ElfSection.from_elf_header(self, offset)
            print(elf_section)


@dataclass
class ElfSection[E: ElfDataEncoding]:
    """Sections contain all information in an object file, except the ELF header,
    the program header table, and the section header table.
    Moreover, object files’ sections satisfy several conditions:

    - Every section in an object file has exactly one section header describing it.
    Section headers may exist that do not have a section.
    - Each section occupies one contiguous (possibly empty) sequence of bytes within a file.
    - Sections in a file may not overlap. Not byte in a file resides in more than one section.
    - An object file may have inactive space. The various headers and the sections might not "cover"
    every byte in an object file. The contents of the inactive data are unspecified.

    ## Special sections

    Name        Type                Attributes
    .bss        SHT_NOBITS          SHF_ALLOC + SHF_WRITE
    .comment    SHT_PROGBITS        none
    .data       SHT_PROGBITS        SHF_ALLOC + SHF_WRITE
    .data1      SHT_PROGBITS        SHF_ALLOC + SHF_WRITE
    .debug      SHT_PROGBITS        none
    .dynamic    SHT_DYNAMIC         see below
    .dynstr     SHT_STRTAB          SHF_ALLOC
    .dynsym     SHT_DYNSYM          SHF_ALLOC
    .fini       SHT_PROGBITS        SHF_ALLOC + SHF_EXECINSTR
    .got        SHT_PROGBITS        see below
    .hash       SHT_HASH            SHF_ALLOC
    .init       SHT_PROGBITS        SHF_ALLOC + SHF_EXECINSTR
    .interp     SHT_PROGBITS        see below
    .line       SHT_PROGBITS        none
    .note       SHT_NOTE            none
    .plt        SHT_PROGBITS        see below
    .relname    SHT_REL             see below
    .relaname   SHT_RELA            see below
    .rodata     SHT_PROGBITS        SHF_ALLOC
    .rodata1    SHT_PROGBITS        SHF_ALLOC
    .shstrtab   SHT_STRTAB          none
    .strtab     SHT_STRTAB          see below
    .symtab     SHT_SYMTAB          see below
    .text       SHT_PROGBITS        SHF_ALLOC + SHF_EXECINSTR
    """

    endianness: E
    """Carries endianness info of the section header."""

    sh_name: int
    """Section name string table index. (4/8 bytes)
    
    This member specifies the name of the section. Its value is an index into the section
    header string table section [see: "String Table"], giving the location of a null-
    terminated string.
    """

    sh_type: SectionHeaderType
    """Section type. (4/8 bytes)
    
    This member categorizes the section's contents and semantics. Section types and their
    descriptions appear below.
    """

    sh_flags: SectionHeaderFlags
    """Section attributes. (4/8 bytes)

    Name                Value
    SHF_WRITE           0x1
    SHF_ALLOC           0x2
    SHF_EXECINSTR       0x4
    SHF_MASKPROC        0xf0000000

    Sections support 1-bit flags that describe miscellaneous attributes. Flag definitions
    appear below.
    """

    sh_addr: int
    """Section virtual address. (4/8 bytes)
    
    If the section will appear in the memory image of a process, this member gives the
    address at which the section's first byte should reside. Otherwise, the member con-
    tains 0.
    """

    sh_offset: int
    """Section file offset. (4/8 bytes)
    
    This member's value gives the byte offset from the beginning of the file to the first
    byte in the section. One section type, SHT_NOBITS described below, occupies no
    space in the file, and its sh_offset member locates the conceptual placement in the
    file.
    """

    sh_size: int
    """Section size in bytes. (4/8 bytes)
    
    This member gives the section's size in bytes. Unless the section type is
    SHT_NOBITS, the section occupies sh_size bytes in the file. A section of type
    SHT_NOBITS may have a non-zero size, but it occupies no space in the file.
    """

    sh_link: int
    """Section header table index link. (4/8 bytes)
    
    This member holds a section header table index link, whose interpretation depends
    on the section type. A table below describes the values.

    sh_type                     sh_link (section header index)                  sh_info
    SHT_DYNAMIC                 String table used by entries in the section.    0
    SHT_HASH                    Symbol table to which the hash table applies.   0
    SHT_REL / SHT_RELA          Associated symbol table.                        The section header index of 
                                                                                the section which the relocation applies.
    SHT_SYMTAB / SHT_DYNSYM     Associated string table.                        One greater than the symbol table index
                                                                                of the last local symbol (binding `STB_LOCAL`)
    other                       SHN_UNDEF                                       0
    """

    sh_info: int
    """Section header table index info. (4/8 bytes)
    
    This member holds extra information, whose interpretation depends on the section
    type. A table below describes the values.
    """

    sh_addralign: int
    """Section address alignment. (4/8 bytes)
    
    Some sections have address alignment constraints. For example, if a section holds a
    doubleword, the system must ensure doubleword alignment for the entire section.
    That is, the value of sh_addr must be congruent to 0, modulo the value of
    sh_addralign. Currently, only 0 and positive integral powers of two are allowed.
    Values 0 and 1 mean the section has no alignment constraints.
    """

    sh_entsize: int
    """Section entry size. (4/8 bytes)
    
    Some sections hold a table of fixed-size entries, such as a symbol table. For such a sec-
    tion, this member gives the size in bytes of each entry. The member contains 0 if the
    section does not hold a table of fixed-size entries.
    """

    def __repr__(self):
        return _pretty(self)

    @classmethod
    def from_elf_header(
        cls, elf_header: ElfHeader[E], section_offset: int
    ) -> "ElfSection[E]":
        section_bytes = elf_header.file_copy[
            section_offset : section_offset + elf_header.e_shentsize
        ]

        if elf_header.e_ident.file_class == ElfFileClass.ELFCLASS32:
            section_bytes = section_bytes[0:32]
        elif elf_header.e_ident.file_class == ElfFileClass.ELFCLASS64:
            section_bytes = section_bytes[0:64]
        else:
            raise ValueError("Invalid ELF file class.")

        endianness_fmt = (
            ">"
            if elf_header.e_ident.data_encoding == ElfDataEncoding.ELFDATA2MSB
            else "<"
        )
        # Choose struct format and unpack exactly the section‐header size
        if elf_header.e_ident.file_class == ElfFileClass.ELFCLASS32:
            # 10 × 4-byte fields: sh_name, sh_type, sh_flags, sh_addr, sh_offset,
            # sh_size, sh_link, sh_info, sh_addralign, sh_entsize
            bin_fmt = f"{endianness_fmt}10I"
        else:
            # ELF64_Shdr: I,I; Q×4; I,I; Q,Q
            # (sh_name, sh_type), (sh_flags, sh_addr, sh_offset, sh_size),
            # (sh_link, sh_info), (sh_addralign, sh_entsize)
            bin_fmt = f"{endianness_fmt}IIQQQQIIQQ"
        header_size = struct.calcsize(bin_fmt)
        # unpack only the exact bytes we need
        header_data = struct.unpack(bin_fmt, section_bytes[:header_size])

        # safe conversion for section type (allow unknown values)
        raw_type = header_data[1]
        try:
            sh_type = SectionHeaderType(raw_type)
        except ValueError:
            sh_type = raw_type
        return cls(
            endianness=elf_header.e_ident.data_encoding,
            sh_name=header_data[0],
            sh_type=sh_type,
            sh_flags=SectionHeaderFlags(header_data[2]),
            sh_addr=header_data[3],
            sh_offset=header_data[4],
            sh_size=header_data[5],
            sh_link=header_data[6],
            sh_info=header_data[7],
            sh_addralign=header_data[8],
            sh_entsize=header_data[9],
        )


def parse_elf_file(filepath: str) -> ElfHeader[ElfDataEncoding]:
    with open(filepath, "rb") as f:
        return ElfHeader.from_file(f)


if __name__ == "__main__":
    try:
        elf_header = parse_elf_file("./example")
        print(elf_header.get_section_header_table())
    except Exception as e:
        print(f"Error parsing ELF file: {e}")
