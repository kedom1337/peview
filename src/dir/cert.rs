use crate::{dir::*, error::*, impl_from_bytes, mem::*};
use core::mem;

/// Attribute certificate
pub struct Certificate<'a> {
    head: &'a CertificateHead,
    data: ByteReader<'a>,
}

impl<'a> Certificate<'a> {
    pub fn new(bytes: &'a [u8], head: &'a CertificateHead) -> Self {
        Self {
            data: ByteReader::new(bytes),
            head,
        }
    }

    /// Returns the `revision` field of the [`CertificateHead`].
    pub fn revision(&self) -> u16 {
        self.head.revision
    }

    /// Returns the `typ` field of the [`CertificateHead`].
    pub fn typ(&self) -> u16 {
        self.head.typ
    }

    /// Returns a reference to the actual certificate data of this [`Certificate`].
    pub fn value(&self) -> &ByteReader<'a> {
        &self.data
    }
}

/// Iterator over the certificate table
pub struct CertificateTable<'a> {
    data: ByteReader<'a>,
}

impl<'a> Iterator for CertificateTable<'a> {
    type Item = Result<Certificate<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.data.read::<CertificateHead>() {
            Ok(head) => {
                let data = &self.data.remaining_bytes()
                    [..head.length as usize - mem::size_of::<CertificateHead>()];

                self.data.skip(SkipPos::Cur(
                    algin_up(head.length as _, 8)
                        - mem::size_of::<CertificateHead>(),
                ));

                Some(Ok(Certificate::new(data, head)))
            }
            Err(Error::InsufficientBuffer) => None,
            Err(e) => Some(Err(e)),
        }
    }
}

impl<'a> DataDirectoryTable<'a> for CertificateTable<'a> {
    fn new(bytes: &'a [u8], _dir: &'a DataDirectory) -> Self {
        Self {
            data: ByteReader::new(bytes),
        }
    }

    fn typ() -> DataDirectoryType {
        DataDirectoryType::CertificateTable
    }
}

/// Native structure define by [MSDN](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-attribute-certificate-table-image-only)
#[derive(Clone, Copy)]
#[repr(C)]
pub struct CertificateHead {
    length: u32,
    revision: u16,
    typ: u16,
}

impl_from_bytes!(CertificateHead);
