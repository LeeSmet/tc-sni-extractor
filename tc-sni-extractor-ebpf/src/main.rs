#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::TC_ACT_PIPE,
    helpers::bpf_skb_load_bytes,
    macros::{classifier, map},
    maps::PerCpuArray,
    programs::TcContext,
};
use aya_log_ebpf::info;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{Ipv4Hdr, Ipv6Hdr},
    tcp::TcpHdr,
};
use tc_sni_extractor_common::SniBuffer;

#[map]
static SNI_BUFFER: PerCpuArray<SniBuffer> = PerCpuArray::with_max_entries(1, 0);

#[classifier]
pub fn tc_sni_extractor(ctx: TcContext) -> i32 {
    match try_tc_sni_extractor(ctx) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_PIPE,
    }
}

fn try_tc_sni_extractor(ctx: TcContext) -> Result<i32, ()> {
    let ethhdr: EthHdr = ctx.load(0).map_err(|_| ())?;
    let iph_len = match ethhdr.ether_type {
        EtherType::Ipv4 => {
            let ipv4hdr: Ipv4Hdr = ctx.load(EthHdr::LEN).map_err(|_| ())?;
            ipv4hdr.ihl() as usize * 4
        }
        EtherType::Ipv6 => Ipv6Hdr::LEN,
        _ => return Ok(TC_ACT_PIPE),
    };

    let tcp_header: TcpHdr = ctx.load(EthHdr::LEN + iph_len).map_err(|_| ())?;
    // size in 32 bit words
    let tcp_header_len =
        ((ctx.load::<u8>(EthHdr::LEN + iph_len + 12).map_err(|_| ())? >> 4) << 2) as usize;
    if u16::from_be(tcp_header.dest) == 443 {
        parse_sni_header(ctx, EthHdr::LEN + iph_len + tcp_header_len)?;
    }
    Ok(TC_ACT_PIPE)
}

fn parse_sni_header(ctx: TcContext, offset: usize) -> Result<i32, ()> {
    let mut pos = offset;
    if ctx.load::<u8>(pos).map_err(|_| ())? != 0x16 {
        // handshake record type
        return Ok(TC_ACT_PIPE);
    }

    if ctx.load::<u8>(pos + 5).map_err(|_| ())? != 0x01 {
        // Client hello
        return Ok(TC_ACT_PIPE);
    }
    // 5 bytes record header
    // 4 bytes handshake header
    // 2 bytes client version
    // 32 bytes client random
    pos += 43;

    let ses_id_len = ctx.load::<u8>(pos).map_err(|_| ())? as usize;
    pos += 1 + ses_id_len;

    let cipher_suite_len = u16::from_be(ctx.load::<u16>(pos).map_err(|_| ())?) as usize;
    pos += 2 + cipher_suite_len;

    let compresion_method_len = ctx.load::<u8>(pos).map_err(|_| ())? as usize;
    pos += 1 + compresion_method_len;

    let extension_len = u16::from_be(ctx.load::<u16>(pos).map_err(|_| ())?) as usize;
    pos += 2;
    let extension_end = pos + extension_len;

    // 16 extensions max
    for _ in 0..16 {
        if pos >= extension_end - 4 {
            break;
        }

        let extension_type = u16::from_be(ctx.load::<u16>(pos).map_err(|_| ())?);
        pos += 2;
        let extension_len = u16::from_be(ctx.load::<u16>(pos).map_err(|_| ())?) as usize;
        pos += 2;

        if extension_type == 0 {
            // ServerName extension
            // skip list length (2) and name type (1)
            pos += 3;
            let mut sni_len = u16::from_be(ctx.load::<u16>(pos).map_err(|_| ())?) as usize;
            pos += 2;
            if sni_len > 64 {
                sni_len = 64;
            }

            if sni_len == 0 || pos as u32 >= ctx.skb.len() {
                break;
            }

            let buf = unsafe {
                let ptr = SNI_BUFFER.get_ptr_mut(0).ok_or(())?;
                &mut *ptr
            };

            if buf.buf.is_empty() {
                break;
            }

            if sni_len > buf.buf.len() {
                sni_len = buf.buf.len();
            }

            load_array(&ctx, pos, &mut buf.buf[..sni_len]).map_err(|_| ())?;

            // FIXME: validate
            // Limit sni_len to 64 bytes
            let sni = unsafe { core::str::from_utf8_unchecked(&buf.buf[..sni_len]) };
            info!(&ctx, "TLS connection to {}", sni);
            break;
        }

        pos += extension_len;
    }

    Ok(TC_ACT_PIPE)
}

#[inline(always)]
pub fn load_array(tc: &TcContext, offset: usize, dst: &mut [u8]) -> Result<usize, ()> {
    let len = usize::try_from(tc.skb.len()).map_err(|core::num::TryFromIntError { .. }| ())?;
    let len = len.checked_sub(offset).ok_or(())?;
    let len = len.min(dst.len());
    if len == 0 {
        return Ok(0);
    }
    let len_u32 = u32::try_from(len).map_err(|core::num::TryFromIntError { .. }| ())?;
    let ret = unsafe {
        bpf_skb_load_bytes(
            tc.skb.skb as *const _,
            offset as u32,
            dst.as_mut_ptr() as *mut _,
            len_u32,
        )
    };
    if ret == 0 {
        Ok(len)
    } else {
        Err(())
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
