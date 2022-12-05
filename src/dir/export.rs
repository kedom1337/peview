use crate::{dir::*, error::*, impl_from_bytes, mem::*};
use alloc::string::ToString;
use core::mem;

/// The value of a single export entry
pub enum ExportValue<'a> {
    /// Normal in-module export, RVA points to exported function
    Rva(u32),
    /// Forwarded export, string contains the module and function name of the export
    Forward(&'a str),
}

/// Export table entry
pub struct Export<'a> {
    /// Value of export
    pub value: ExportValue<'a>,
    /// Ordinal index
    pub ordinal: u16,
    /// Name of the export
    pub name: Option<&'a str>,
}

/// Iterator over the export table located in .edata
pub struct ExportTable<'a> {
    data: ByteReader<'a>,
    dir: &'a DataDirectory,
    export_table: Option<&'a ExportDirectoryTable>,
    index: (u16, usize),
}

impl<'a> ExportTable<'a> {
    /// Check if the [`ExportDirectoryTable`] has already been parsed.
    /// If it has, return it.
    /// If not, try to parse and validate it before advancing the internal buffer to the first EAT entry.
    ///
    /// # Errors
    ///
    /// This function will return an error if it was unable to parse the table
    /// or the table was malformed
    pub fn export_table(&mut self) -> Result<&'a ExportDirectoryTable> {
        if self.export_table.is_none() {
            let etable = self.data.read::<ExportDirectoryTable>()?.validate()?;
            self.data.skip(SkipPos::Rel(etable.function_rva as _));

            Ok(self.export_table.insert(etable))
        } else {
            Ok(self.export_table.unwrap())
        }
    }

    /// Returns the `time_date_stamp` field of the [`ExportDirectoryTable`]
    ///
    /// # Errors
    ///
    /// This function will return an error if it was unable to retrieve the [`ExportDirectoryTable`]
    pub fn time_date_stamp(&mut self) -> Result<u32> {
        Ok(self.export_table()?.time_date_stamp)
    }

    /// Returns the `num_of_funcs` field of the [`ExportDirectoryTable`]
    ///
    /// # Errors
    ///
    /// This function will return an error if it was unable to retrieve the [`ExportDirectoryTable`]
    pub fn func_count(&mut self) -> Result<u32> {
        Ok(self.export_table()?.num_of_funcs)
    }

    /// Returns the `num_of_names` field of the [`ExportDirectoryTable`]
    ///
    /// # Errors
    ///
    /// This function will return an error if it was unable to retrieve the [`ExportDirectoryTable`]
    pub fn name_count(&mut self) -> Result<u32> {
        Ok(self.export_table()?.num_of_names)
    }
}

impl<'a> DataDirectoryTable<'a> for ExportTable<'a> {
    fn new(bytes: &'a [u8], dir: &'a DataDirectory) -> Self {
        Self {
            data: ByteReader::new_with_rel(bytes, dir.rva as usize),
            dir,
            export_table: None,
            index: (0, 0),
        }
    }

    fn typ() -> DataDirectoryType {
        DataDirectoryType::ExportTable
    }
}

impl<'a> Iterator for ExportTable<'a> {
    type Item = Result<Export<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        // Get the EDT
        let etable = match self.export_table() {
            Ok(v) => v,
            Err(e) => return Some(Err(e)),
        };

        // Check if the iterator reached the end of the EAT
        if etable.num_of_funcs <= self.index.0 as u32 {
            return None;
        }

        match (|| {
            // Read the next EAT and EOT entry
            let rva = self.data.read::<u32>()?;
            let ordinal = self.data.read_at::<u16>(
                etable.ordinals_rva as usize + mem::size_of::<u16>() * self.index.1,
            )?;

            // Check if the EOT entry corresponds to a ENPT entry
            let name = if self.index.0 == *ordinal {
                let name_rva = self.data.read_at::<u32>(
                    etable.names_rva as usize + mem::size_of::<u32>() * self.index.1,
                )?;

                Some(str_from_bytes(self.data.bytes_at(*name_rva as usize)?)?)
            } else {
                None
            };

            // Advance the EAT and EOT entry indices
            self.index.0 += 1;
            if name.is_some() {
                self.index.1 += 1;
            }

            // Check if the current EAT entry is a forward export or a normal RVA
            let value = if self.dir.contains_rva(*rva) {
                ExportValue::Forward(str_from_bytes(
                    self.data.bytes_at(*rva as usize)?,
                )?)
            } else {
                ExportValue::Rva(*rva)
            };

            Ok(Export {
                value,
                ordinal: etable.ordinal_base as u16 + self.index.0 - 1,
                name,
            })
        })() {
            Ok(v) => Some(Ok(v)),
            Err(e) => Some(Err(e)),
        }
    }
}

/// Native structure define by [MSDN](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#export-directory-table)
#[derive(Clone, Copy)]
#[repr(C)]
pub struct ExportDirectoryTable {
    pub characteristics: u32,
    pub time_date_stamp: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub name_rva: u32,
    pub ordinal_base: u32,
    pub num_of_funcs: u32,
    pub num_of_names: u32,
    pub function_rva: u32,
    pub names_rva: u32,
    pub ordinals_rva: u32,
}

impl ExportDirectoryTable {
    pub fn validate(&self) -> Result<&Self> {
        if self.characteristics != 0 {
            return Error::make_malformed::<ExportDirectoryTable, _>(
                "has non zero reserved field 'characteristics'".to_string(),
            );
        }

        if self.num_of_funcs < self.num_of_names {
            return Error::make_malformed::<ExportDirectoryTable, _>(
                "has invalid number of functions or names".to_string(),
            );
        }

        if (self.names_rva == 0 && self.ordinals_rva != 0)
            || (self.names_rva != 0 && !self.ordinals_rva == 0)
        {
            return Error::make_malformed::<ExportDirectoryTable, _>(
                "has invalid rva to name or ordinal table".to_string(),
            );
        }

        Ok(self)
    }
}

impl_from_bytes!(ExportDirectoryTable);
