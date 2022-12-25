#![feature(error_in_core, cstr_from_bytes_until_nul)]
#![no_std]
#![doc = include_str!("../README.md")]

extern crate alloc;

pub mod dir;
pub mod error;
pub mod file;
pub mod header;
pub mod mem;
pub mod section;
