//! Minimal ELF32 (little-endian, RISC-V) loader: `PT_LOAD` segments only.
//!
//! Executable segments become the read-only code image (the public program table);
//! all other segments become the initial RAM image, including the zero-filled tail
//! (`p_memsz > p_filesz`, i.e. `.bss` and the stack).

use std::collections::BTreeMap;

#[derive(Clone, Debug, Default)]
pub struct Image {
    pub entry: u32,
    /// Word-aligned address -> instruction word.
    pub code: BTreeMap<u32, u32>,
    /// Word-aligned address -> initial data word.
    pub data: BTreeMap<u32, u32>,
}

const PT_LOAD: u32 = 1;
const PF_X: u32 = 1;
const EM_RISCV: u16 = 243;

fn u16_at(b: &[u8], o: usize) -> Result<u16, String> {
    b.get(o..o + 2).map(|s| u16::from_le_bytes([s[0], s[1]])).ok_or_else(|| "truncated ELF".into())
}
fn u32_at(b: &[u8], o: usize) -> Result<u32, String> {
    b.get(o..o + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
        .ok_or_else(|| "truncated ELF".into())
}

impl Image {
    pub fn from_elf(bytes: &[u8]) -> Result<Image, String> {
        if bytes.get(0..4) != Some(b"\x7fELF") {
            return Err("not an ELF file".into());
        }
        if bytes[4] != 1 || bytes[5] != 1 {
            return Err("expected ELF32 little-endian".into());
        }
        if u16_at(bytes, 18)? != EM_RISCV {
            return Err("not a RISC-V ELF".into());
        }
        let entry = u32_at(bytes, 24)?;
        let phoff = u32_at(bytes, 28)? as usize;
        let phentsize = u16_at(bytes, 42)? as usize;
        let phnum = u16_at(bytes, 44)? as usize;

        let mut img = Image { entry, ..Default::default() };
        for i in 0..phnum {
            let ph = phoff + i * phentsize;
            if u32_at(bytes, ph)? != PT_LOAD {
                continue;
            }
            let offset = u32_at(bytes, ph + 4)? as usize;
            let vaddr = u32_at(bytes, ph + 8)?;
            let filesz = u32_at(bytes, ph + 16)? as usize;
            let memsz = u32_at(bytes, ph + 20)?;
            let flags = u32_at(bytes, ph + 24)?;
            let file = bytes.get(offset..offset + filesz).ok_or("segment out of file bounds")?;

            let byte_at = |a: u32| -> u8 {
                let k = a.wrapping_sub(vaddr) as usize;
                if a >= vaddr && k < filesz {
                    file[k]
                } else {
                    0
                }
            };
            let target = if flags & PF_X != 0 { &mut img.code } else { &mut img.data };
            let (start, end) = (vaddr & !3, (vaddr + memsz + 3) & !3);
            for a in (start..end).step_by(4) {
                let w = u32::from_le_bytes([byte_at(a), byte_at(a + 1), byte_at(a + 2), byte_at(a + 3)]);
                let e = target.entry(a).or_insert(0);
                *e |= w;
            }
        }
        Ok(img)
    }
}
