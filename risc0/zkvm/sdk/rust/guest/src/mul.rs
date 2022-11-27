use core::{cell::UnsafeCell, mem};

use crate::env::log;
use _alloc::format;
use _alloc::{boxed::Box, vec::Vec};
use risc0_zkvm::platform::{
    io::{MulDescriptor, GPIO_MUL},
    memory,
};

// Current sha descriptor index.
struct CurOutput(UnsafeCell<usize>);

// SAFETY: single threaded environment
unsafe impl Sync for CurOutput {}

static CUR_OUTPUT: CurOutput = CurOutput(UnsafeCell::new(0));

/// Result of multiply goldilocks
pub struct MulGoldilocks([u32; 4]);

impl MulGoldilocks {
    /// Get the result as u64
    pub fn get_u64(&self) -> [u64; 2] {
        [
            (self.0[1] as u64) | ((self.0[0] as u64) << 32),
            (self.0[3] as u64) | ((self.0[2] as u64) << 32),
        ]
    }
}

fn alloc_output() -> *mut MulDescriptor {
    // SAFETY: Single threaded and this is the only place we use CUR_DESC.
    unsafe {
        let cur_desc = CUR_OUTPUT.0.get();
        let ptr = (memory::MUL.start() as *mut MulDescriptor).add(*cur_desc);
        *cur_desc += 1;
        ptr
    }
}

/// Multiply goldilocks oracle, verification is done separately
pub fn mul_goldilocks(a: &[u64; 2], b: &[u64; 2]) -> &'static MulGoldilocks {
    let a0_hi = ((a[0] & 0xFFFFFFFF00000000) >> 32) as u32;
    let a0_lo = (a[0] & 0xFFFFFFFF) as u32;
    let a1_hi = ((a[1] & 0xFFFFFFFF00000000) >> 32) as u32;
    let a1_lo = (a[1] & 0xFFFFFFFF) as u32;

    let b0_hi = ((b[0] & 0xFFFFFFFF00000000) >> 32) as u32;
    let b0_lo = (b[0] & 0xFFFFFFFF) as u32;
    let b1_hi = ((b[1] & 0xFFFFFFFF00000000) >> 32) as u32;
    let b1_lo = (b[1] & 0xFFFFFFFF) as u32;

    let buf = [a0_hi, a0_lo, a1_hi, a1_lo, b0_hi, b0_lo, b1_hi, b1_lo];

    unsafe {
        let alloced = Box::<mem::MaybeUninit<MulGoldilocks>>::new(
            mem::MaybeUninit::<MulGoldilocks>::uninit(),
        );
        let output = (*Box::into_raw(alloced)).as_mut_ptr();
        mul_raw(&buf[..], output);
        &*output
    }
}

pub(crate) unsafe fn mul_raw(data: &[u32], result: *mut MulGoldilocks) {
    let output_ptr = alloc_output();

    let ptr = data.as_ptr();
    super::memory_barrier(ptr);
    output_ptr.write_volatile(MulDescriptor {
        source: ptr as usize,
        result: result as usize,
    });

    GPIO_MUL.as_ptr().write_volatile(output_ptr);
}
