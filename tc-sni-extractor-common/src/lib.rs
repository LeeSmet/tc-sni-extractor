#![no_std]

#[cfg(feature = "user")]
use aya::Pod;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SniBuffer {
    pub buf: [u8; 64],
}

#[cfg(feature = "user")]
unsafe impl Pod for SniBuffer {}
