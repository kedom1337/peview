use crate::{dir::*, error::*, header::*, mem::*, section::Section};
use alloc::vec::Vec;
use core::mem;

/// Address that represents a position within a [`PeView`]
#[derive(Clone, Copy)]
pub enum PeAddr {
    /// Relative virtual address
    Rva(u32),
    /// Absolute offset within the file
    FilePtr(u32),
}

/// View of a PE32+ file
pub struct PeView<'a> {
    dos_header: &'a DosHeader,
    nt_header: &'a NtHeader,
    sections: Vec<Section<'a>>,
    data: ByteReader<'a>,
}

impl<'a> PeView<'a> {
    /// Creates a [`PeView`] of a PE32+ file by parsing and validating the
    /// specified raw byte buffer representing it.
    ///
    /// # Errors
    ///
    /// This function will return an error if the byte buffer does not
    /// represent a valid and complete PE32+ file.
    pub fn parse(bytes: &'a [u8]) -> Result<Self> {
        // Create an interface for easily reading the buffer
        let mut data = ByteReader::new(bytes);

        // Read and validate both the DOS- and NT-header
        let dos_header = data.read::<DosHeader>()?.validate()?;
        let nt_header = data
            .skip(SkipPos::Rel(dos_header.e_lfanew as _))
            .read::<NtHeader>()?
            .validate()?;

        // Jump to the RVA of the first section header
        data.skip(SkipPos::Rel(
            dos_header.e_lfanew as usize
                + mem::size_of::<u32>()
                + mem::size_of::<FileHeader>()
                + nt_header.file_header.size_of_optional_header as usize,
        ));

        // Allocate a vector for holding the sections
        let mut sections =
            Vec::with_capacity(nt_header.file_header.num_of_sections as _);

        // Iterate over each section header and save its section after validation
        for _ in 0..nt_header.file_header.num_of_sections {
            sections.push(Section::parse(
                bytes,
                data.read::<SectionHeader>()?
                    .validate(&nt_header.optional_header)?,
            )?)
        }

        Ok(Self {
            dos_header,
            nt_header,
            sections,
            data,
        })
    }

    /// Returns a reference to the DOS-header of this [`PeView`].
    pub fn dos_header(&self) -> &DosHeader {
        self.dos_header
    }

    /// Returns a reference to the NT-header of this [`PeView`].
    pub fn nt_header(&self) -> &NtHeader {
        self.nt_header
    }

    /// Returns a reference to the sections of this [`PeView`].
    pub fn sections(&self) -> &[Section] {
        self.sections.as_ref()
    }

    /// Returns a reference to a single section of this [`PeView`],
    /// who's raw data contains the specified address.
    ///
    /// Returns [`None`] if no such section is found.
    pub fn section_by_addr(&self, addr: PeAddr) -> Option<&Section> {
        self.sections
            .iter()
            .find(|s| !s.empty() && s.contains_addr(addr))
    }

    /// Returns a reference to a single section of this [`PeView`],
    /// who's name is equal to the one specified.
    ///
    /// Returns [`None`] if no such section is found.
    pub fn section_by_name(&self, name: &str) -> Option<&Section> {
        self.sections.iter().find(|s| s.name() == name)
    }

    /// Checks if specified flag is contained in the file headers characteristics.
    pub fn has_flag(&self, flag: FileFlags) -> bool {
        self.nt_header.file_header.characteristics & flag as u16 == 1
    }

    /// Returns a reference to the data directory of the specified type.
    ///
    /// Returns [`None`] if the data directory is empty
    pub fn directory(&self, typ: DataDirectoryType) -> Option<&DataDirectory> {
        let directory =
            &self.nt_header.optional_header.data_directories[typ as usize];

        if directory.size > 0 {
            Some(directory)
        } else {
            None
        }
    }

    /// Returns a fallible iterator over the export table
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    /// - The [`DataDirectoryType::ExportTable`] data directory is empty ([`Error::DataDirectoryEmpty`])
    /// - The .edata section is empty or not found ([`Error::SectionEmpty`])
    /// - The export table is malformed
    pub fn exports(&self) -> Result<ExportTable> {
        self.directory_table(DataDirectoryType::ExportTable)
    }

    /// Returns a fallible iterator over the import table
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    /// - The [`DataDirectoryType::ImportTable`] data directory is empty ([`Error::DataDirectoryEmpty`])
    /// - The .idata section is empty or not found ([`Error::SectionEmpty`])
    /// - The import table is malformed
    pub fn imports(&self) -> Result<ImportTable> {
        self.directory_table(DataDirectoryType::ImportTable)
    }

    /// Returns a fallible iterator over the base relocation table
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    /// - The [`DataDirectoryType::RelocationTable`] data directory is empty ([`Error::DataDirectoryEmpty`])
    /// - The .reloc section is empty or not found ([`Error::SectionEmpty`])
    /// - The base relocation table is malformed
    pub fn relocations(&self) -> Result<RelocationTable> {
        self.directory_table(DataDirectoryType::RelocationTable)
    }

    /// Returns a fallible iterator over the certificate table
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    /// - The [`DataDirectoryType::CertificateTable`] data directory is empty ([`Error::DataDirectoryEmpty`])
    /// - The certificate table is malformed
    pub fn certificates(&self) -> Result<CertificateTable> {
        self.directory_table(DataDirectoryType::CertificateTable)
    }

    /// Internal method for abstracting over the process of getting
    /// parsed tables for the raw data contained in the specified data directories
    fn directory_table<T>(&'a self, typ: DataDirectoryType) -> Result<T>
    where
        T: DataDirectoryTable<'a>,
    {
        // Get the data directory and raw data of table
        let directory = self.directory(typ).ok_or(Error::DataDirectoryEmpty)?;
        let data = match typ {
            DataDirectoryType::CertificateTable => &self.data,
            _ => self
                .section_by_addr(PeAddr::Rva(directory.addr))
                .ok_or(Error::SectionEmpty)?
                .data()
                .as_ref()
                .unwrap(),
        };

        // Validate the length of the sections raw data
        if data.bytes().len() <= directory.size as usize {
            return Err(Error::InsufficientBuffer);
        }

        // Get a slice of the sections raw data which contains the required table
        let bytes = match typ {
            DataDirectoryType::ExportTable
            | DataDirectoryType::RelocationTable
            | DataDirectoryType::CertificateTable => {
                &data.bytes_at(directory.addr as _)?[..directory.size as _]
            }
            DataDirectoryType::ImportTable => data.bytes_at(directory.addr as _)?,
            _ => unimplemented!(),
        };

        // Return the actual table
        Ok(T::new(bytes, directory))
    }
}
