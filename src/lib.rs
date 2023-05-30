#![feature(error_in_core)]
#![no_std]
#![doc = include_str!("../README.md")]

extern crate alloc;

pub mod dir;
pub mod error;
pub mod file;
pub mod header;
pub mod mem;
pub mod section;
