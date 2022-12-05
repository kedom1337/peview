# peview

A minimal and fast zero-copy parser for the PE32+ file format.

[![Build status](https://github.com/kedom1337/peview/workflows/ci/badge.svg)](https://github.com/kedom1337/peview/actions)
[![Docs.rs](https://img.shields.io/docsrs/peview)](https://docs.rs/peview/latest/peview)
[![Crates.io](https://img.shields.io/crates/v/peview.svg)](https://crates.io/crates/peview)

## Goal

This project aims to offer a more light weight and easier to use alternative to 
fully featured binary parsing libraries when it comes to parsing the PE32+ file format. It does so by:

- Taking a zero-copy approach. Everything is a reference to the original data
- Parsing on demand. Basic parsing is done at the beginning, the rest is opt-in
- Not focusing on endianness. The parsed buffer is assumed to be in LE
- Strong validation of native structures

## Usage

Example of printing the RVA's and names of imported symbols

```rust
// Read target file into buffer
let mut buf = Vec::new();
File::open("etc/ntoskrnl.exe")?.read_to_end(&mut buf)?;
// Initialize the parser, does basic validation
let pe = PeView::parse(&buf)?;

// Iterate over modules in the import table
for m in pe.imports()? {
    let module = m?;

    // Iterate over symbols within the module
    for i in module {
        // Check if the symbol is imported by name
        if let Import::Name(h, n) = i? {
            // Print out both the hint and its name
            println!("{:#04x}: {}", h, n);
        }
    }
}

```
## Installation

Add the following line to your Cargo.toml file:

```toml
[dependencies]
# ...
peview = "0.1.0"
```

## License

[MIT](https://choosealicense.com/licenses/mit/)
