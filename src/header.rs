use crate::{dir::DataDirectory, error::*, impl_from_bytes, mem::FromBytes};
use alloc::{format, string::ToString};
use core::{mem, str};

/// Native structure
#[derive(Clone, Copy)]
#[repr(C)]
pub struct DosHeader {
    pub e_magic: u16,
    pub e_cblp: u16,
    pub e_cp: u16,
    pub e_crlc: u16,
    pub e_cparhdr: u16,
    pub e_minalloc: u16,
    pub e_maxalloc: u16,
    pub e_ss: u16,
    pub e_sp: u16,
    pub e_csum: u16,
    pub e_ip: u16,
    pub e_cs: u16,
    pub e_lfarlc: u16,
    pub e_ovno: u16,
    pub e_res: [u16; 4],
    pub e_oemid: u16,
    pub e_oeminfo: u16,
    pub e_res2: [u16; 10],
    pub e_lfanew: u32,
}

impl DosHeader {
    const DOS_SIGNATURE: u16 = 0x5A4D;

    pub fn validate(&self) -> Result<&Self> {
        if self.e_magic != Self::DOS_SIGNATURE {
            return Error::make_malformed::<Self, _>(format!(
                "has invalid magic number ({:#04x})",
                self.e_magic
            ));
        }

        if self.e_lfanew as usize % mem::size_of::<u32>() != 0 {
            return Error::make_malformed::<Self, _>(format!(
                "has invalid new header rva ({:#08x})",
                self.e_lfanew
            ));
        }

        Ok(self)
    }
}

/// Native structure define by [MSDN](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#coff-file-header-object-and-image)
#[derive(Clone, Copy)]
#[repr(C)]
pub struct FileHeader {
    pub machine: u16,
    pub num_of_sections: u16,
    pub time_date_stamp: u32,
    pub ptr_to_symbol_table: u32,
    pub num_of_symbols: u32,
    pub size_of_optional_header: u16,
    pub characteristics: u16,
}

pub enum FileMachine {
    I386 = 0x014c,
    IA64 = 0x0200,
    AMD64 = 0x8664,
}

pub enum FileFlags {
    RelocsStripped = 0x1,
    ExecutableImage = 0x2,
    LargeAddress = 0x20,
    Machine32 = 0x100,
    DebugStripped = 0x200,
    RemovableRun = 0x400,
    NetworkRun = 0x800,
    SystemFile = 0x1000,
    Dll = 0x2000,
    UpSystemOnly = 0x4000,
}

impl FileHeader {
    const MIN_NUM_OF_SECTIONS: u16 = 2;
    const MAX_NUM_OF_SECTIONS: u16 = 96;

    pub fn validate(&self) -> Result<&Self> {
        if self.machine != FileMachine::AMD64 as u16
            && self.machine != FileMachine::I386 as u16
            && self.machine != FileMachine::IA64 as u16
        {
            return Error::make_malformed::<Self, _>(format!(
                "has invalid machine architecture ({:#04x})",
                self.machine
            ));
        }

        if self.num_of_sections < Self::MIN_NUM_OF_SECTIONS
            || self.num_of_sections > Self::MAX_NUM_OF_SECTIONS
        {
            return Error::make_malformed::<Self, _>(format!(
                "has invalid number of sections ({})",
                self.num_of_sections
            ));
        }

        if self.size_of_optional_header == 0 {
            return Err(Error::InvalidFileFormat);
        }

        if self.characteristics == 0 {
            return Error::make_malformed::<Self, _>(
                "has missing characteristics".to_string(),
            );
        }

        Ok(self)
    }
}

/// Native structure define by [MSDN](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#optional-header-image-only)
#[derive(Clone, Copy)]
#[repr(C)]
pub struct OptionalHeader {
    pub magic: u16,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub address_of_entry_point: u32,
    pub base_of_code: u32,
    pub image_base: u64,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub major_os_version: u16,
    pub minor_os_version: u16,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub win32_version_value: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub check_sum: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub size_of_stack_reserve: u64,
    pub size_of_stack_commit: u64,
    pub size_of_heap_reserve: u64,
    pub size_of_heap_commit: u64,
    pub loader_flags: u32,
    pub num_of_rva_and_sizes: u32,
    pub data_directories: [DataDirectory; 16],
}

impl OptionalHeader {
    const NT_PAGE_SIZE: u32 = 0x1000;
    const NT_OPTIONAL_HDR64_MAGIC: u16 = 0x20B;

    pub fn validate(&self) -> Result<&Self> {
        if self.magic != Self::NT_OPTIONAL_HDR64_MAGIC {
            return Err(Error::InvalidFileFormat);
        }

        if self.image_base % 0x10000 != 0 {
            return Error::make_malformed::<Self, _>(format!(
                "has invalid image base ({:#016x})",
                self.image_base
            ));
        }

        if self.section_alignment < self.file_alignment {
            return Error::make_malformed::<Self, _>(format!(
                "has invalid section alignment ({:#08x})",
                self.section_alignment
            ));
        }

        if self.file_alignment % 2 != 0
            || self.file_alignment < 512
            || self.file_alignment > 0x10000
            || (self.section_alignment < Self::NT_PAGE_SIZE
                && self.file_alignment != self.section_alignment)
        {
            return Error::make_malformed::<Self, _>(format!(
                "has invalid file alignment ({:#08x})",
                self.file_alignment
            ));
        }

        if self.win32_version_value != 0 {
            return Error::make_malformed::<Self, _>(
                "has non zero reserved field 'win32_version_value'".to_string(),
            );
        }

        if self.size_of_image % self.section_alignment != 0 {
            return Error::make_malformed::<Self, _>(format!(
                "has invalid size of image ({:#08x})",
                self.size_of_image
            ));
        }

        if self.size_of_headers % self.file_alignment != 0 {
            return Error::make_malformed::<Self, _>(format!(
                "has invalid size of headers ({:#08x})",
                self.size_of_headers
            ));
        }

        if self.loader_flags != 0 {
            return Error::make_malformed::<Self, _>(
                "has non zero reserved field 'loader_flags'".to_string(),
            );
        }

        Ok(self)
    }
}

/// Native structure
#[derive(Clone, Copy)]
#[repr(C)]
pub struct NtHeader {
    pub signature: u32,
    pub file_header: FileHeader,
    pub optional_header: OptionalHeader,
}

impl NtHeader {
    const NT_SIGNATURE: u32 = 0x00004550;

    pub fn validate(&self) -> Result<&Self> {
        if self.signature != Self::NT_SIGNATURE {
            return Error::make_malformed::<Self, _>(format!(
                "has invalid signature ({:#08x})",
                self.signature
            ));
        }

        self.file_header.validate()?;
        self.optional_header.validate()?;

        Ok(self)
    }
}

/// Native structure define by [MSDN](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#section-table-section-headers)
#[derive(Clone, Copy)]
#[repr(C)]
pub struct SectionHeader {
    pub name: [u8; 8],
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub raw_data_size: u32,
    pub raw_data_address: u32,
    pub ptr_to_relocations: u32,
    pub ptr_to_linenumbers: u32,
    pub num_of_relocations: u16,
    pub num_of_linenumbers: u16,
    pub characteristics: u32,
}

#[repr(u32)]
pub enum SectionFlags {
    CntCode = 0x20,
    CntInitData = 0x40,
    CntUninitData = 0x80,
    Gprel = 0x8000,
    NrelocOvfl = 0x1000000,
    Discardable = 0x2000000,
    NotCached = 0x4000000,
    NotPaged = 0x8000000,
    Shared = 0x10000000,
    Execute = 0x20000000,
    Read = 0x40000000,
    Write = 0x80000000,
}

impl SectionHeader {
    pub fn validate(&self, optional_header: &OptionalHeader) -> Result<&Self> {
        str::from_utf8(self.name.as_slice())
            .map_err(|e| Error::Malformed(e.to_string()))?;

        if self.raw_data_size % optional_header.file_alignment != 0 {
            return Error::make_malformed::<Self, _>(format!(
                "has invalid size of raw data ({:#08x})",
                self.raw_data_size
            ));
        }

        if self.raw_data_address % optional_header.file_alignment != 0 {
            return Error::make_malformed::<Self, _>(format!(
                "has invalid address of raw data ({:#08x})",
                self.raw_data_address
            ));
        }

        if (self.virtual_size == 0 && self.raw_data_size == 0)
            || (self.virtual_address == 0 && self.raw_data_address == 0)
        {
            return Error::make_malformed::<Self, _>(
                "has invalid section size or address".to_string(),
            );
        }

        Ok(self)
    }
}

impl_from_bytes!(
    DosHeader,
    FileHeader,
    OptionalHeader,
    NtHeader,
    SectionHeader
);
