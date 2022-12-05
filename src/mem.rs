use crate::error::*;
use alloc::string::ToString;
use core::{ffi::CStr, mem};

/// Creates a [`str`] slice from the specified bytes.
///
/// # Errors
///
/// This function will return [`Error::Malformed`]
/// if the bytes do not represent a valid, null-terminated UTF-8 string.
pub fn str_from_bytes(bytes: &[u8]) -> Result<&str> {
    CStr::from_bytes_until_nul(bytes)
        .map_err(|e| Error::Malformed(e.to_string()))?
        .to_str()
        .map_err(|e| Error::Malformed(e.to_string()))
}

/// Position to where [`ByteReader`] should advance it's internal buffer to
pub enum SkipPos {
    /// Position is relative to the current position
    Cur(usize),
    /// Position is relative to the relative position specified with [`ByteReader::new_with_rel`]
    Rel(usize),
}

/// Interface to safely read plain data which implements [`FromBytes`] from a [`u8`] slice
pub struct ByteReader<'a> {
    bytes: &'a [u8],
    pos: usize,
    rel_pos: Option<usize>,
}

impl<'a> ByteReader<'a> {
    /// Creates a new [`ByteReader`] over the specified bytes.
    pub fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            pos: 0,
            rel_pos: None,
        }
    }

    /// Creates a new relative [`ByteReader`] over the specified bytes.
    ///
    /// All operations including RVA's will be relative to the specified position.
    pub fn new_with_rel(bytes: &'a [u8], pos: usize) -> Self {
        Self {
            bytes,
            pos: 0,
            rel_pos: Some(pos),
        }
    }

    /// Returns a reference to the bytes of this [`ByteReader`].
    pub fn bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// Returns a reference to the remaining bytes of this [`ByteReader`].
    pub fn remaining_bytes(&self) -> &'a [u8] {
        &self.bytes[self.pos..]
    }

    /// Returns a reference to the bytes of this [`ByteReader`], starting at the specified position
    ///
    /// # Errors
    ///
    /// This function will return [`Error::InsufficientBuffer`]
    /// if the specified position is outside of the buffers bounds.
    pub fn bytes_at(&self, pos: usize) -> Result<&'a [u8]> {
        self.bytes
            .get(self.pos_to_rel(pos)..)
            .ok_or(Error::InsufficientBuffer)
    }

    /// Returns the relative position set by [`ByteReader::new_with_rel`] of this [`ByteReader`].
    pub fn rel_pos(&self) -> Option<usize> {
        self.rel_pos
    }

    /// Converts the specified RVA to a position within the buffer
    pub fn pos_to_rel(&self, pos: usize) -> usize {
        pos - self.rel_pos.unwrap_or(0)
    }

    /// Advances the internal data buffer to the specified position
    pub fn skip(&mut self, pos: SkipPos) -> &mut Self {
        match pos {
            SkipPos::Cur(v) => self.pos += v,
            SkipPos::Rel(v) => self.pos = self.pos_to_rel(v),
        }

        self
    }

    /// Reads a plain data structure implementing [`FromBytes`] from the current position
    ///
    /// # Errors
    ///
    /// This function will return an error if the current position is invalid
    /// or the bytes at the current position do not have the right memory layout for the requested
    /// structure
    pub fn read<T>(&mut self) -> Result<&'a T>
    where
        T: FromBytes,
    {
        // Read the structure at the current position
        let res = T::from_bytes(
            self.bytes
                .get(self.pos..)
                .ok_or(Error::InsufficientBuffer)?,
        )?;

        // Advance the buffer by the size of the read structure
        self.pos += mem::size_of::<T>();

        Ok(res)
    }

    /// Reads a plain data structure implementing [`FromBytes`] from the specified position
    ///
    /// # Errors
    ///
    /// This function will return an error if the specified position is invalid
    /// or the bytes at the current position do not have the right memory layout for the requested
    /// structure
    pub fn read_at<T>(&self, pos: usize) -> Result<&'a T>
    where
        T: FromBytes,
    {
        T::from_bytes(
            self.bytes
                .get(self.pos_to_rel(pos)..)
                .ok_or(Error::InsufficientBuffer)?,
        )
    }
}

///Allows for reading plain data structures from a [`u8`] slice
///
/// # Safety
///
/// This trait and its operations are only safe for structures which are purely composed of plain
/// data and have a C-style memory layout aka. #[repr(C)]
pub unsafe trait FromBytes: Copy {
    /// Returns a reference to a single instance of [`Self`] represented by the specified bytes.
    /// Does not check for correct endianness.
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    /// - The buffer is not big enough to read the requested structure ([`Error::InsufficientBuffer`])
    /// - The buffers memory alignment is not ABI complaint with the requested structure ([`Error::Misaligned`])
    fn from_bytes(bytes: &[u8]) -> Result<&Self>
    where
        Self: Sized,
    {
        // Check if the buffer is large enough
        if mem::size_of::<Self>() > 0 && bytes.len() < mem::size_of::<Self>() {
            return Err(Error::InsufficientBuffer);
        }

        // Check if the buffer is aligned correctly
        if bytes.as_ptr() as usize % mem::align_of::<Self>() != 0 {
            return Err(Error::Misaligned);
        }

        // Interpret the bytes as a reference to [`Self`]
        Ok(unsafe { &*(bytes.as_ptr().cast()) })
    }
}

#[macro_export]
macro_rules! impl_from_bytes {
    ($($struct_name:ident),+ $(,)?) => {
        $(
            unsafe impl FromBytes for $struct_name { }
        )+
    }
}

// Implement [`FromBytes`] for the default unsigned integer types
impl_from_bytes!(u8, u16, u32, u64);
