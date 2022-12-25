mod relocation;
pub use relocation::*;
mod import;
pub use import::*;
mod export;
pub use export::*;

#[derive(Clone, Copy)]
pub enum DataDirectoryType {
    ExportTable,
    ImportTable,
    ResourceTable,
    ExceptionTable,
    CertificateTable,
    RelocationTable,
    Debug,
    Architecture,
    GlobalPointer,
    TLSTable,
    LoadConfigTable,
    BoundImportTable,
    ImportAddressTable,
    DelayImportDescriptor,
    CLRRuntimeHeader,
    Reserved,
}

/// Native structure define by [MSDN](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#optional-header-data-directories-image-only)
#[derive(Clone, Copy)]
#[repr(C)]
pub struct DataDirectory {
    pub addr: u32,
    pub size: u32,
}

impl DataDirectory {
    /// Checks if the specified RVA is within the bounds of this [`DataDirectory`]
    pub fn contains_addr(&self, addr: u32) -> bool {
        (self.addr..self.addr + self.size).contains(&addr)
    }
}

pub trait DataDirectoryTable<'a> {
    fn new(bytes: &'a [u8], dir: &'a DataDirectory) -> Self;

    /// Returns the [`DataDirectoryType`] of this table
    fn typ() -> DataDirectoryType;
}
