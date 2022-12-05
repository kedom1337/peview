use crate::{dir::*, error::*, impl_from_bytes, mem::*};
use core::mem;

/// Import entry of a module
pub enum Import<'a> {
    /// Hint and name of imported symbol
    Name(u16, &'a str),
    /// Ordinal value
    Ordinal(u16),
}

/// Iterator over the import entries of a single module
pub struct ImportModule<'a> {
    data: ByteReader<'a>,
    dir: &'a ImportDirectoryEntry,
}

impl<'a> ImportModule<'a> {
    pub fn new(
        data: &'a [u8],
        data_rva: usize,
        dir: &'a ImportDirectoryEntry,
    ) -> Self {
        let mut data = ByteReader::new_with_rel(data, data_rva);
        data.skip(SkipPos::Rel(dir.lookup_rva as _));

        Self { data, dir }
    }

    /// Returns the `time_date_stamp` field of the [`ImportDirectoryEntry`].
    pub fn time_date_stamp(&self) -> u32 {
        self.dir.time_date_stamp
    }

    /// Returns the `forwarder_chain` field of the [`ImportDirectoryEntry`].
    pub fn forwarder(&self) -> u32 {
        self.dir.forwarder_chain
    }

    /// Returns the parsed name of the [`ImportDirectoryEntry`].
    pub fn name(&self) -> Result<&str> {
        str_from_bytes(self.data.bytes_at(self.dir.name_rva as _)?)
    }

    /// Returns the `address_rva` field of the [`ImportDirectoryEntry`].
    pub fn address_rva(&self) -> u32 {
        self.dir.address_rva
    }
}

impl<'a> Iterator for ImportModule<'a> {
    type Item = Result<Import<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        // Read the next ILT entry
        match self.data.read::<ImportEntry>() {
            Ok(entry) => {
                // If the entry is zero, it means we reached the end of the table
                if entry == &ImportEntry::default() {
                    return None;
                }

                // Check if the symbol is imported by ordinal or name
                let import = if entry.is_ordinal() {
                    Import::Ordinal(entry.value() as u16)
                } else {
                    match (|| {
                        // Parse the string of the H/NT entry
                        let hint = self.data.read_at::<u16>(entry.value() as _)?;
                        let name = str_from_bytes(self.data.bytes_at(
                            entry.value() as usize + mem::size_of::<u16>(),
                        )?)?;

                        Ok((*hint, name))
                    })() {
                        Ok((o, n)) => Import::Name(o, n),
                        Err(e) => return Some(Err(e)),
                    }
                };

                Some(Ok(import))
            }
            Err(e) => Some(Err(e)),
        }
    }
}

/// Iterator over the import table located in .idata
pub struct ImportTable<'a> {
    data: ByteReader<'a>,
}

impl<'a> DataDirectoryTable<'a> for ImportTable<'a> {
    fn new(bytes: &'a [u8], dir: &'a DataDirectory) -> Self {
        Self {
            data: ByteReader::new_with_rel(bytes, dir.rva as usize),
        }
    }

    fn typ() -> DataDirectoryType {
        DataDirectoryType::ImportTable
    }
}

impl<'a> Iterator for ImportTable<'a> {
    type Item = Result<ImportModule<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        // Read the next IDT entry
        match self.data.read::<ImportDirectoryEntry>() {
            Ok(dir) => {
                // If the entry is zero, it means we reached the end of the table
                if dir == &ImportDirectoryEntry::default() {
                    return None;
                }

                Some(Ok(ImportModule::new(
                    self.data.bytes(),
                    self.data.rel_pos().unwrap(),
                    dir,
                )))
            }
            Err(e) => Some(Err(e)),
        }
    }
}

/// Native structure define by [MSDN](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#import-directory-table)
#[derive(Clone, Copy, PartialEq, Eq, Default)]
#[repr(C)]
pub struct ImportDirectoryEntry {
    pub lookup_rva: u32,
    pub time_date_stamp: u32,
    pub forwarder_chain: u32,
    pub name_rva: u32,
    pub address_rva: u32,
}

/// Native structure define by [MSDN](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#import-lookup-table)
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub struct ImportEntry(u64);

impl ImportEntry {
    pub fn value(&self) -> u32 {
        (self.0 & 0x00000000FFFFFFFF) as u32
    }

    pub fn is_ordinal(&self) -> bool {
        (self.0 >> 63) == 1
    }
}

impl_from_bytes!(ImportDirectoryEntry, ImportEntry);
