use crate::{error::*, file::PeAddr, header::*, mem::ByteReader};
use core::str;

/// Section of a PE32+ file
pub struct Section<'a> {
    header: &'a SectionHeader,
    data: Option<ByteReader<'a>>,
}

impl<'a> Section<'a> {
    /// Creates the [`Section`] of a PE32+ which is represented by the specified header
    ///
    /// # Errors
    ///
    /// This function will return an error if the byte buffer does not hold
    /// a valid and complete section
    pub fn parse(bytes: &'a [u8], header: &'a SectionHeader) -> Result<Self> {
        // Check if section contains any raw data
        let data = if header.raw_data_size > 0 {
            // Get a slice of the PE32+ bytes which holds the sections raw data
            let bytes = bytes
                .get(
                    header.raw_data_address as _
                        ..(header.raw_data_address + header.raw_data_size) as _,
                )
                .ok_or(Error::InsufficientBuffer)?;

            Some(ByteReader::new_with_rel(bytes, header.virtual_address as _))
        } else {
            None
        };

        Ok(Self { header, data })
    }

    /// Returns a reference to the header of this [`Section`].
    pub fn header(&self) -> &SectionHeader {
        self.header
    }

    /// Returns a reference to the data of this [`Section`].
    pub fn data(&self) -> &Option<ByteReader<'a>> {
        &self.data
    }

    /// Returns a reference to the name of this [`Section`].
    ///
    /// # Panics
    ///
    /// Panics if the raw bytes in the sections header are not a valid UTF-8 string.
    ///
    /// This can be ensured by calling [`SectionHeader::validate`] before
    /// passing the header to [`Section::parse`].
    ///
    /// The above is automatically done by [`crate::file::PeView::parse`].
    pub fn name(&self) -> &str {
        str::from_utf8(self.header.name.as_slice()).unwrap()
    }

    /// Checks if the specified flag is contained in the headers characteristics.
    pub fn has_flag(&self, flag: SectionFlags) -> bool {
        self.header.characteristics & flag as u32 == 1
    }

    /// Checks if the section has no raw data.
    pub fn empty(&self) -> bool {
        self.data.is_none()
    }

    /// Checks if the specified address is contained within the sections raw data.
    pub fn contains_addr(&self, addr: PeAddr) -> bool {
        let range = match addr {
            PeAddr::Rva(rva) => {
                (self.header.virtual_address, self.header.virtual_size, rva)
            }
            PeAddr::FilePtr(ptr) => {
                (self.header.raw_data_address, self.header.raw_data_size, ptr)
            }
        };

        (range.0..range.0 + range.1).contains(&range.2)
    }
}
