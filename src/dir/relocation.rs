use crate::{dir::*, error::*, impl_from_bytes, mem::*};
use alloc::format;
use core::mem;

/// Relocation entry of a relocation block
/// Values are defined by [MSDN](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#base-relocation-types)
pub enum Relocation {
    Absolute(u16),
    High(u16),
    Low(u16),
    HighLow(u16),
    HighAdj(u16),
    MipsArmRiscv(u16),
    ThumbRiscv(u16),
    RiscvLoong(u16),
    JmpAddr(u16),
    Dir64(u16),
}

/// Iterator over the entries of a single relocation block
pub struct RelocationBlock<'a> {
    head: &'a RelocationHead,
    data: ByteReader<'a>,
}

impl<'a> RelocationBlock<'a> {
    pub fn new(data: &'a [u8], head: &'a RelocationHead) -> Self {
        Self {
            data: ByteReader::new(data),
            head,
        }
    }

    /// Returns the `page_rva` field of the [`RelocationHead`].
    pub fn page_rva(&self) -> u32 {
        self.head.page_rva
    }

    /// Returns the number of entries in this [`RelocationBlock`].
    pub fn entry_count(&self) -> usize {
        (self.head.block_size as usize - mem::size_of::<RelocationHead>())
            / mem::size_of::<RelocationEntry>()
    }
}

impl<'a> Iterator for RelocationBlock<'a> {
    type Item = Result<Relocation>;

    fn next(&mut self) -> Option<Self::Item> {
        match (|| {
            // Read and convert the next BR entry
            let entry = self.data.read::<RelocationEntry>()?;
            Relocation::try_from(entry)
        })() {
            Ok(v) => Some(Ok(v)),
            Err(Error::InsufficientBuffer) => None,
            Err(e) => Some(Err(e)),
        }
    }
}

/// Iterator over the relocation table located in .reloc
pub struct RelocationTable<'a> {
    data: ByteReader<'a>,
}

impl<'a> DataDirectoryTable<'a> for RelocationTable<'a> {
    fn new(bytes: &'a [u8], _dir: &'a DataDirectory) -> Self {
        Self {
            data: ByteReader::new(bytes),
        }
    }

    fn typ() -> DataDirectoryType {
        DataDirectoryType::RelocationTable
    }
}

impl<'a> Iterator for RelocationTable<'a> {
    type Item = Result<RelocationBlock<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        // Read the next BRB entry
        match self.data.read::<RelocationHead>() {
            Ok(head) => {
                // Check if we reached the end of the table
                if head.block_size == 0
                    || head.block_size as usize % mem::size_of::<u32>() != 0
                {
                    return None;
                }

                let data = &self.data.remaining_bytes()
                    [..head.block_size as usize - mem::size_of::<RelocationHead>()];
                self.data.skip_to(Pos::Rel(data.len()));

                Some(Ok(RelocationBlock::new(data, head)))
            }
            Err(Error::InsufficientBuffer) => None,
            Err(e) => Some(Err(e)),
        }
    }
}

/// Native structure define by [MSDN](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#base-relocation-block)
#[derive(Clone, Copy)]
#[repr(C)]
pub struct RelocationHead {
    pub page_rva: u32,
    pub block_size: u32,
}

/// Native structure define by [MSDN](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#base-relocation-block)
#[derive(Clone, Copy)]
pub struct RelocationEntry(u16);

impl RelocationEntry {
    pub fn offset(&self) -> u16 {
        self.0 & 0x0FFF
    }

    pub fn kind(&self) -> u16 {
        self.0 >> 12
    }
}

impl TryFrom<&RelocationEntry> for Relocation {
    type Error = Error;

    fn try_from(value: &RelocationEntry) -> core::result::Result<Self, Self::Error> {
        use Relocation::*;

        Ok(match value.kind() {
            0x0 => Absolute(value.offset()),
            0x1 => High(value.offset()),
            0x2 => Low(value.offset()),
            0x3 => HighLow(value.offset()),
            0x4 => HighAdj(value.offset()),
            0x5 => MipsArmRiscv(value.offset()),
            0x7 => ThumbRiscv(value.offset()),
            0x8 => RiscvLoong(value.offset()),
            0x9 => JmpAddr(value.offset()),
            0xA => Dir64(value.offset()),
            _ => {
                return Error::make_malformed::<RelocationEntry, _>(format!(
                    "has invalid type ({})",
                    value.kind()
                ))
            }
        })
    }
}

impl_from_bytes!(RelocationHead, RelocationEntry);
