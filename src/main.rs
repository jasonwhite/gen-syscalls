#![feature(str_strip)]

use std::collections::HashMap;
use std::fs;
use std::io;
use std::mem;
use std::path::{Path, PathBuf};
use std::slice;

use goblin::elf::{section_header::SectionHeader, sym::Sym, Elf};
use scroll::Pread;
use serde::Serialize;
use structopt::StructOpt;

#[derive(StructOpt)]
struct Opts {
    /// Path to the vmlinux ELF image. By default, `/boot/vmlinux-$(uname -r)`
    /// is used. This must contain debug information so that we can search
    /// through the symbol table for syscall metadata symbols.
    #[structopt()]
    vmlinux: Option<PathBuf>,

    /// Output in JSON format.
    #[structopt(long)]
    json: bool,
}

/// Metadata associated with a syscall. This is defined in
/// [`include/trace/syscall.h`][syscall_metadata].
///
/// [syscall_metadata]: https://elixir.bootlin.com/linux/v5.5.3/source/include/trace/syscall.h
#[repr(C)]
#[derive(Debug, Pread)]
struct SyscallMetadata {
    /// Address of the syscall name.
    name: u64,

    /// Number of the syscall. This is always set to -1. The Kernel sets this to
    /// the real syscall number upon boot. Since we are reading the ELF file, we
    /// need to look through `sys_call_table` to find out the real syscall
    /// number.
    syscall_nr: libc::c_int,

    /// Number of parameters it takes.
    nb_args: libc::c_int,

    /// List of types as strings.
    types: u64,

    /// List of parameters as strings (args[i] matches types[i]).
    args: u64,
    // Don't care about these fields.
    //struct list_head enter_fields;
    //struct trace_event_call *enter_event;
    //struct trace_event_call *exit_event;
}

fn find_sym(elf: &Elf, search: &str) -> Option<Sym> {
    for sym in elf.syms.iter() {
        if let Some(name) = elf.strtab.get(sym.st_name) {
            let name = name.unwrap();
            if name == search {
                return Some(sym);
            }
        }
    }

    None
}

fn find_section<'a>(elf: &'a Elf, search: &'a str) -> Option<&'a SectionHeader> {
    for sh in &elf.section_headers {
        if let Some(name) = elf.shdr_strtab.get(sh.sh_name) {
            let name = name.unwrap();
            if name == search {
                return Some(sh);
            }
        }
    }

    None
}

fn get_array<'a, T>(elf: &'a Elf, buf: &'a [u8], sym: Sym) -> &'a [T] {
    let count = sym.st_size as usize / mem::size_of::<T>();

    let sh = &elf.section_headers[sym.st_shndx];

    let offset = sym.st_value - sh.sh_addr + sh.sh_offset;

    unsafe { slice::from_raw_parts(buf.as_ptr().add(offset as usize).cast::<T>(), count) }
}

fn sym_offset(elf: &Elf, sym: Sym) -> usize {
    let sh = &elf.section_headers[sym.st_shndx];
    let offset = sym.st_value - sh.sh_addr + sh.sh_offset;
    offset as usize
}

fn get_syscall_table<'a>(elf: &'a Elf, buf: &'a [u8]) -> Option<&'a [libc::c_ulong]> {
    let sym = find_sym(&elf, "sys_call_table")?;
    Some(get_array(elf, buf, sym))
}

#[derive(Debug, Serialize)]
struct SyscallInfo {
    pub num: usize,
    pub name: String,
    pub params: Vec<(String, String)>,
}

fn syscall_list(path: &Path) -> Result<Vec<SyscallInfo>, Box<dyn std::error::Error>> {
    let buf = fs::read(path)?;

    let elf = Elf::parse(&buf)?;

    // This is a table of all the addresses of architecture-specific syscall
    // symbols. We use this to create a mapping of syscall IDs to symbol names.
    let table = match get_syscall_table(&elf, &buf) {
        Some(table) => table,
        None => return Err("Failed to find `sys_call_table`".into()),
    };

    // The syscall symbols live in this section.
    let text_section = match find_section(&elf, ".text") {
        Some(sec) => sec,
        None => return Err("Failed to find .text section".into()),
    };

    // The syscall symbols live in this section.
    let data_section = match find_section(&elf, ".data") {
        Some(sec) => sec,
        None => return Err("Failed to find .data section".into()),
    };

    // Create a mapping of syscall symbol names to syscall numbers.
    let mapping: HashMap<_, _> = elf
        .syms
        .iter()
        .filter_map(|sym| {
            table
                .iter()
                .position(|&addr| addr == sym.st_value)
                .and_then(|id| {
                    // Look up the name, stripping off the `__x64_` prefix.
                    // TODO: Don't assume x64 architecture. Derive the prefix somehow.
                    let name = elf.strtab.get(sym.st_name)?.ok()?.strip_prefix("__x64_")?;
                    Some((name, id))
                })
        })
        .collect();

    let mut list = Vec::new();

    for sym in elf.syms.iter() {
        if let Some(sym_name) = elf.strtab.get(sym.st_name) {
            let sym_name = sym_name?;

            if sym_name.starts_with("__syscall_meta") {
                let syscall: SyscallMetadata = buf.pread(sym_offset(&elf, sym))?;

                // Look up the name in the .text section.
                let name_offset = syscall.name - text_section.sh_addr + text_section.sh_offset;
                let name: &str = buf.pread(name_offset as usize)?;

                if let Some(&nr) = mapping.get(name) {
                    let mut types = Vec::new();

                    // Chase pointers and gather arg types
                    if syscall.types != 0 {
                        let mut types_offset = (syscall.types - data_section.sh_addr
                            + data_section.sh_offset)
                            as usize;

                        for _ in 0..syscall.nb_args {
                            let addr: u64 = buf.gread(&mut types_offset)?;
                            let offset = addr - text_section.sh_addr + text_section.sh_offset;
                            let name: &str = buf.pread(offset as usize)?;
                            types.push(name);
                        }
                    }

                    let mut args = Vec::new();

                    // Chase pointers and gather arg names
                    if syscall.args != 0 {
                        let mut args_offset =
                            (syscall.args - data_section.sh_addr + data_section.sh_offset) as usize;

                        for _ in 0..syscall.nb_args {
                            let addr: u64 = buf.gread(&mut args_offset)?;
                            let offset = addr - text_section.sh_addr + text_section.sh_offset;
                            let name: &str = buf.pread(offset as usize)?;
                            args.push(name);
                        }
                    }

                    let params = types
                        .into_iter()
                        .zip(args)
                        .map(|(t, a)| (t.to_string(), a.to_string()))
                        .collect();

                    list.push(SyscallInfo {
                        num: nr,
                        name: name.into(),
                        params,
                    });
                }
            }
        }
    }

    Ok(list)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Opts::from_args();

    let vmlinux = match args.vmlinux {
        Some(vmlinux) => vmlinux,
        None => {
            // Use /boot/vmlinux-$(uname -r) by default.
            PathBuf::from(format!(
                "/boot/vmlinux-{}",
                nix::sys::utsname::uname().release()
            ))
        }
    };

    let mut list = syscall_list(&vmlinux)?;
    list.sort_by_key(|syscall| syscall.num);

    if args.json {
        let stdout = io::stdout();
        let mut stdout = stdout.lock();
        serde_json::to_writer_pretty(&mut stdout, &list)?;
    } else {
        for syscall in &list {
            println!(
                "{:>3} => {}({})",
                syscall.num,
                syscall.name,
                syscall
                    .params
                    .iter()
                    .map(|(t, a)| format!("{} {}", t, a))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
    }

    Ok(())
}
