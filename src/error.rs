use alloc::{format, string::String};
use core::{
    any, error,
    fmt::{self, Display, Formatter},
    result,
};

pub type Result<T> = result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    Misaligned,
    InsufficientBuffer,
    Malformed(String),
    InvalidFileFormat,
    DataDirectoryEmpty,
    SectionEmpty,
}

impl Error {
    pub fn make_malformed<T, R>(m: String) -> Result<R> {
        let type_name = any::type_name::<T>();
        Err(Self::Malformed(format!("{type_name} {m}")))
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let msg = match self {
            Self::Misaligned => "provided buffer is misaligned",
            Self::InsufficientBuffer => "provided buffer is too small",
            Self::Malformed(m) => m,
            Self::InvalidFileFormat => "only x64 (PE32+) files are supported",
            Self::DataDirectoryEmpty => "required data directory is empty",
            Self::SectionEmpty => "required section has no raw data",
        };

        write!(f, "Error ({self:?}) {msg}")
    }
}

impl error::Error for Error {}
