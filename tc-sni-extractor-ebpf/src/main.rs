#![no_std]
#![no_main]

use aya_ebpf::{bindings::TC_ACT_PIPE, macros::classifier, programs::TcContext};
use aya_log_ebpf::info;

#[classifier]
pub fn tc_sni_extractor(ctx: TcContext) -> i32 {
    match try_tc_sni_extractor(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_tc_sni_extractor(ctx: TcContext) -> Result<i32, i32> {
    info!(&ctx, "received a packet");
    Ok(TC_ACT_PIPE)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
