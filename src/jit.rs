// SPDX-License-Identifier: (Apache-2.0 OR MIT)
// Derived from uBPF <https://github.com/iovisor/ubpf>
// Copyright 2015 Big Switch Networks, Inc
//      (uBPF: JIT algorithm, originally in C)
// Copyright 2016 6WIND S.A. <quentin.monnet@6wind.com>
//      (Translation to Rust, MetaBuff addition)

#![allow(clippy::single_match)]

use core::ptr::NonNull;
use core::slice;
use std::alloc;
use std::collections::HashMap;
use std::fmt::Error as FormatterError;
use std::fmt::Formatter;
use std::io::Error;
use std::mem;
use std::ops::{Index, IndexMut};

use crate::ebpf;

#[cfg(target_arch = "x86_64")]
mod x86;

#[cfg(target_arch = "x86_64")]
pub use x86::JitCompiler;

type MachineCode = unsafe fn(*mut u8, usize, *mut u8, usize, usize, usize) -> u64;

const PAGE_SIZE: usize = 4096;
// TODO: check how long the page must be to be sure to support an eBPF program of maximum possible
// length
const NUM_PAGES: usize = 1;

// Special values for target_pc in struct Jump
const TARGET_OFFSET: isize = ebpf::PROG_MAX_INSNS as isize;
const TARGET_PC_EXIT: isize = TARGET_OFFSET + 1;

#[derive(Copy, Clone)]
enum OperandSize {
    S8 = 8,
    S16 = 16,
    S32 = 32,
    S64 = 64,
}

pub struct JitMemory {
    contents: NonNull<u8>,
    layout: alloc::Layout,
    offset: usize,
}

impl JitMemory {
    pub fn new(
        prog: &[u8],
        helpers: &HashMap<u32, ebpf::Helper>,
        use_mbuff: bool,
        update_data_ptr: bool,
    ) -> Result<JitMemory, Error> {
        let layout;

        // Allocate the appropriately sized memory.
        let contents = unsafe {
            // Create a layout with the proper size and alignment.
            let size = NUM_PAGES * PAGE_SIZE;
            layout = alloc::Layout::from_size_align_unchecked(size, PAGE_SIZE);

            // Allocate the region of memory.
            let ptr = alloc::alloc(layout);
            if ptr.is_null() {
                return Err(Error::from(std::io::ErrorKind::OutOfMemory));
            }

            // Protect it.
            libc::mprotect(ptr.cast(), size, libc::PROT_EXEC | libc::PROT_WRITE);
            NonNull::new_unchecked(ptr)
        };

        let mut mem = JitMemory {
            contents,
            layout,
            offset: 0,
        };

        let mut jit = JitCompiler::new();
        jit.jit_compile(&mut mem, prog, use_mbuff, update_data_ptr, helpers)?;
        jit.resolve_jumps(&mut mem)?;

        Ok(mem)
    }

    pub fn get_prog(&self) -> MachineCode {
        unsafe { mem::transmute(self.contents) }
    }
}

impl Index<usize> for JitMemory {
    type Output = u8;

    fn index(&self, _index: usize) -> &u8 {
        let data = unsafe { slice::from_raw_parts(self.contents.as_ptr(), self.layout.size()) };
        &data[_index]
    }
}

impl IndexMut<usize> for JitMemory {
    fn index_mut(&mut self, _index: usize) -> &mut u8 {
        let data = unsafe { slice::from_raw_parts_mut(self.contents.as_ptr(), self.layout.size()) };
        &mut data[_index]
    }
}

impl Drop for JitMemory {
    fn drop(&mut self) {
        unsafe {
            alloc::dealloc(self.contents.as_ptr(), self.layout);
        }
    }
}

impl std::fmt::Debug for JitMemory {
    fn fmt(&self, fmt: &mut Formatter) -> Result<(), FormatterError> {
        fmt.write_str("JIT contents: [")?;
        fmt.write_str(" ] | ")?;
        fmt.debug_struct("JIT memory")
            .field("offset", &self.offset)
            .finish()
    }
}
