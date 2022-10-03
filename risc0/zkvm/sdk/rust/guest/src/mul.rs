use core::{cell::UnsafeCell, mem};

use _alloc::{boxed::Box, vec::Vec};
use risc0_zkvm::platform::{io::{MulDescriptor, GPIO_MUL}, memory};

// Current sha descriptor index.
struct CurOutput(UnsafeCell<usize>);

// SAFETY: single threaded environment
unsafe impl Sync for CurOutput {}

static CUR_OUTPUT: CurOutput = CurOutput(UnsafeCell::new(0));

pub struct MulGoldilocks([u32; 2]);

fn alloc_output() -> *mut MulDescriptor {
    // SAFETY: Single threaded and this is the only place we use CUR_DESC.
    unsafe {
        let cur_desc = CUR_OUTPUT.0.get();
        let ptr = (memory::MUL.start() as *mut MulDescriptor).add(*cur_desc);
        *cur_desc += 1;
        ptr
    }
}

pub fn mul_goldilocks(a: &u64, b: &u64) -> &'static MulGoldilocks {
    // Allocate fresh memory that's guaranteed to be uninitialized so
    // the host can write to it.
    let mut buf = Vec::<u32>::with_capacity(4);
    let a_hi = (u32)((a & 0xFFFFFFFF00000000LL) >> 32);
    let a_lo = (u32)(a & 0xFFFFFFFFLL);

    let b_hi = (u32)((b & 0xFFFFFFFF00000000LL) >> 32);
    let b_lo = (u32)(b & 0xFFFFFFFFLL);

    buf.push(a_hi);
    buf.push(a_lo);
    buf.push(b_hi);
    buf.push(b_lo);

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
