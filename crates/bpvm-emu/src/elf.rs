//! Minimal ELF32 (little-endian, RISC-V) loader: `PT_LOAD` segments only.
//!
//! Executable segments become the read-only code image (the public program table);
//! all other segments become the initial RAM image, including the zero-filled tail
//! (`p_memsz > p_filesz`, i.e. `.bss` and the stack).
//!
//! Guest I/O variables are global symbols placed in sections named
//! `.bpvm.<kind>.<type>` (see `guest/common/bpvm.h`); they are collected into [`Image::io`].

use std::collections::BTreeMap;

#[derive(Clone, Debug, Default)]
pub struct Image {
    pub entry: u32,
    /// Word-aligned address -> instruction word.
    pub code: BTreeMap<u32, u32>,
    /// Word-aligned address -> initial data word.
    pub data: BTreeMap<u32, u32>,
    /// I/O variables declared by the guest, sorted by address.
    pub io: Vec<IoVar>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IoKind {
    /// Set by the host before execution; part of the public statement.
    PublicInput,
    /// Set by the host before execution; hidden, bound by Pedersen commitments.
    PrivateInput,
    /// Read after execution; revealed in the statement.
    PublicOutput,
    /// Read after execution; hidden, bound by Pedersen commitments.
    PrivateOutput,
}

impl IoKind {
    pub fn is_input(self) -> bool {
        matches!(self, IoKind::PublicInput | IoKind::PrivateInput)
    }
    pub fn is_private(self) -> bool {
        matches!(self, IoKind::PrivateInput | IoKind::PrivateOutput)
    }
}

/// Element type of an I/O variable (from the C type name in the section name).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IoType {
    U8,
    U32,
    U64,
}

impl IoType {
    pub fn bytes(self) -> u32 {
        match self {
            IoType::U8 => 1,
            IoType::U32 => 4,
            IoType::U64 => 8,
        }
    }
}

/// A guest I/O variable: `count` elements of type `ty` at `addr`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IoVar {
    pub name: String,
    pub kind: IoKind,
    pub ty: IoType,
    pub addr: u32,
    pub count: u32,
}

impl IoVar {
    /// Word addresses of element `i` (meaningful for 32/64-bit elements).
    pub fn words(&self, i: u32) -> Vec<u32> {
        let a = self.addr + i * self.ty.bytes();
        (0..self.ty.bytes().div_ceil(4)).map(|k| a + 4 * k).collect()
    }
}

impl IoVar {
    /// Addresses of all words covering the variable (it is word-aligned).
    pub fn all_words(&self) -> Vec<u32> {
        let n = (self.count * self.ty.bytes()).div_ceil(4);
        (0..n).map(|k| self.addr + 4 * k).collect()
    }

    /// Pack element values into the words covering the variable (padding bytes are zero).
    pub fn to_words(&self, values: &[u64]) -> Vec<(u32, u32)> {
        let w = self.ty.bytes() as usize;
        let mut bytes: Vec<u8> = values.iter().flat_map(|v| v.to_le_bytes()[..w].to_vec()).collect();
        bytes.resize(self.all_words().len() * 4, 0);
        self.all_words().into_iter().zip(bytes.chunks(4)).map(|(a, c)| (a, u32::from_le_bytes([c[0], c[1], c[2], c[3]]))).collect()
    }

    /// Unpack element values from memory.
    pub fn from_words(&self, word: impl Fn(u32) -> u32) -> Vec<u64> {
        let bytes: Vec<u8> = self.all_words().into_iter().flat_map(|a| word(a).to_le_bytes()).collect();
        let w = self.ty.bytes() as usize;
        bytes.chunks(w).take(self.count as usize).map(|c| c.iter().rev().fold(0u64, |acc, b| acc << 8 | *b as u64)).collect()
    }
}

fn parse_io_section(name: &str) -> Result<Option<(IoKind, IoType)>, String> {
    let Some(rest) = name.strip_prefix(".bpvm.") else { return Ok(None) };
    let (kind, ty) = rest.split_once('.').ok_or_else(|| format!("bad I/O section {name}"))?;
    let kind = match kind {
        "public_input" => IoKind::PublicInput,
        "private_input" => IoKind::PrivateInput,
        "public_output" => IoKind::PublicOutput,
        "private_output" => IoKind::PrivateOutput,
        _ => return Err(format!("unknown I/O kind in section {name}")),
    };
    let ty = match ty {
        "uint8_t" | "u8" => IoType::U8,
        "uint32_t" | "u32" => IoType::U32,
        "uint64_t" | "u64" => IoType::U64,
        _ => return Err(format!("unsupported I/O type in section {name} (uint8_t, uint32_t, uint64_t)")),
    };
    Ok(Some((kind, ty)))
}

fn cstr(b: &[u8], o: usize) -> Result<&str, String> {
    let s = b.get(o..).ok_or("string out of bounds")?;
    let end = s.iter().position(|&c| c == 0).ok_or("unterminated string")?;
    std::str::from_utf8(&s[..end]).map_err(|_| "non-UTF-8 name".into())
}

const PT_LOAD: u32 = 1;
/// Sanity limit for one segment (a proof covers far fewer memory words anyway).
const MAX_SEGMENT: u32 = 1 << 28;
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
        if bytes.get(4..6) != Some(&[1, 1][..]) {
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
            if memsz > MAX_SEGMENT {
                return Err(format!("segment of {memsz} bytes is larger than {MAX_SEGMENT}"));
            }
            let end = vaddr.checked_add(memsz).and_then(|e| e.checked_add(3)).ok_or("segment beyond 4 GiB")?;
            let (start, end) = (vaddr & !3, end & !3);
            for a in (start..end).step_by(4) {
                let w = u32::from_le_bytes([byte_at(a), byte_at(a + 1), byte_at(a + 2), byte_at(a + 3)]);
                let e = target.entry(a).or_insert(0);
                *e |= w;
            }
        }
        img.io = io_vars(bytes)?;
        Ok(img)
    }
}

const SHT_SYMTAB: u32 = 2;

/// Collect symbols that live in `.bpvm.*` sections.
fn io_vars(b: &[u8]) -> Result<Vec<IoVar>, String> {
    let shoff = u32_at(b, 32)? as usize;
    let shentsize = u16_at(b, 46)? as usize;
    let shnum = u16_at(b, 48)? as usize;
    let shstrndx = u16_at(b, 50)? as usize;
    if shoff == 0 || shnum == 0 {
        return Ok(Vec::new());
    }
    let sh = |i: usize, field: usize| u32_at(b, shoff + i * shentsize + field);
    let shstr = sh(shstrndx, 16)? as usize;
    let mut sections = Vec::with_capacity(shnum);
    for i in 0..shnum {
        sections.push(parse_io_section(cstr(b, shstr + sh(i, 0)? as usize)?)?);
    }

    let mut vars = Vec::new();
    for i in 0..shnum {
        if sh(i, 4)? != SHT_SYMTAB {
            continue;
        }
        let (off, size, entsize) = (sh(i, 16)? as usize, sh(i, 20)? as usize, sh(i, 36)? as usize);
        if entsize < 16 {
            return Err("bad symbol table entry size".into());
        }
        let strtab = sh(sh(i, 24)? as usize, 16)? as usize;
        for k in 1..size / entsize {
            let e = off + k * entsize;
            let shndx = u16_at(b, e + 14)? as usize;
            let Some(Some((kind, ty))) = sections.get(shndx) else { continue };
            let info = *b.get(e + 12).ok_or("truncated ELF")?;
            if info & 0xf != 1 {
                continue; // not STT_OBJECT
            }
            let name = cstr(b, strtab + u32_at(b, e)? as usize)?.to_string();
            let (addr, bytes) = (u32_at(b, e + 4)?, u32_at(b, e + 8)?);
            if bytes == 0 || bytes % ty.bytes() != 0 {
                return Err(format!("I/O variable {name}: size {bytes} is not a multiple of its element size"));
            }
            if addr % 4 != 0 {
                return Err(format!("I/O variable {name} must be word-aligned"));
            }
            vars.push(IoVar { name, kind: *kind, ty: *ty, addr, count: bytes / ty.bytes() });
        }
    }
    vars.sort_by_key(|v| v.addr);
    Ok(vars)
}
