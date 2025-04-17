import struct
from dataclasses import dataclass
from enum import Enum
from pprint import pprint
from typing import BinaryIO


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


@dataclass(repr=True)
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


@dataclass(repr=True)
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

    @classmethod
    def from_file(cls, file: BinaryIO) -> "ElfHeader[ElfDataEncoding]":
        """Parses an ELF header from a file handle."""
        try:
            e_ident = ElfIdentifier.from_bytes(file.read(16))
        except ValueError as e:
            raise ValueError(f"Invalid ELF identifier: {e}")

        endianness_fmt = (
            ">" if e_ident.data_encoding == ElfDataEncoding.ELFDATA2MSB else "<"
        )
        is_64bit = e_ident.file_class == ElfFileClass.ELFCLASS64

        # Describe binary format for struct.unpack
        # For 64-bit ELF, we use 'Q' for 8-byte values instead of 'I'
        bin_fmt = (
            f"{endianness_fmt}"  # Endianness
            + "HH"  # e_type, e_machine
            + "I"  # e_version
            + f"{'Q' if is_64bit else 'I'}" * 3  # e_entry, e_phoff, e_shoff
            + "I"  # e_flags
            + "HHHHHH"  # e_ehsize through e_shstrndx
        )

        # Read and unpack the rest of the header
        header_data = struct.unpack(bin_fmt, file.read(struct.calcsize(bin_fmt)))

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
        )


def parse_elf_file(filepath: str) -> ElfHeader[ElfDataEncoding]:
    with open(filepath, "rb") as f:
        return ElfHeader.from_file(f)


if __name__ == "__main__":
    try:
        pprint(parse_elf_file("./example"))
    except Exception as e:
        print(f"Error parsing ELF file: {e}")
