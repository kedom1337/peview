use peview::{
    dir::{ExportValue, Import, Relocation},
    file::PeView,
};
use std::{error::Error, fs::File, io::Read};

#[test]
fn it_parses_relocations() -> Result<(), Box<dyn Error>> {
    let mut buf = Vec::new();
    File::open("etc/ntoskrnl.exe")?.read_to_end(&mut buf)?;
    let pe = PeView::parse(&buf)?;

    const CHECKED_INDEX: usize = 560;

    let mut reloc_count = 0;
    for i in pe.relocations()? {
        let block = i?;

        if reloc_count == CHECKED_INDEX {
            assert_eq!(block.page_rva(), 0x3000);
        }

        for j in block {
            if let Relocation::Dir64(v) = j? {
                reloc_count += 1;

                if reloc_count == CHECKED_INDEX {
                    assert_eq!(v, 0x18);
                }
            }
        }
    }

    assert_eq!(reloc_count, 10048);

    Ok(())
}

#[test]
fn it_parses_imports() -> Result<(), Box<dyn Error>> {
    let mut buf = Vec::new();
    File::open("etc/ntoskrnl.exe")?.read_to_end(&mut buf)?;
    let pe = PeView::parse(&buf)?;

    const CHECKED_INDEX: usize = 118;

    let mut import_count = 0;
    for i in pe.imports()? {
        let module = i?;

        if import_count == CHECKED_INDEX {
            assert_eq!(module.name()?, "kdcom.dll");
        }

        for j in module {
            if let Import::Name(h, n) = j? {
                import_count += 1;

                if import_count == CHECKED_INDEX {
                    assert_eq!(n, "KdPower");
                    assert_eq!(h, 1);
                }
            }
        }
    }

    assert_eq!(import_count, 179);

    Ok(())
}

#[test]
fn it_parses_exports() -> Result<(), Box<dyn Error>> {
    let mut buf = Vec::new();
    File::open("etc/ntoskrnl.exe")?.read_to_end(&mut buf)?;
    let pe = PeView::parse(&buf)?;

    const CHECKED_INDEX: usize = 1987;

    let mut export_count = 0;
    for i in pe.exports()? {
        let export = i?;
        if let Some(n) = export.name {
            if let ExportValue::Rva(v) = export.value {
                export_count += 1;

                if export_count == CHECKED_INDEX {
                    assert_eq!(n, "RtlClearBit");
                    assert_eq!(v, 0x338560);
                }
            }
        }
    }

    assert_eq!(export_count, 3064);

    Ok(())
}

#[test]
fn it_parses_cert() -> Result<(), Box<dyn Error>> {
    let mut buf = Vec::new();
    File::open("etc/ntoskrnl.exe")?.read_to_end(&mut buf)?;
    let pe = PeView::parse(&buf)?;

    for i in pe.certificates()? {
        let cert = i?;
        assert_eq!(cert.value().bytes().len(), 0x2560);
        assert_eq!(cert.revision(), 0x200);
        assert_eq!(cert.typ(), 2);
    }

    Ok(())
}
