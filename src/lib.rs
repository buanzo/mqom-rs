//! Experimental, native Rust implementation of MQOM v2.
//!
//! The first target is `MQOM2-L1-gf16-short-r5` from MQOM v2.1.1.
//! This crate is research software. It has not been independently audited and
//! must not be used to protect sensitive data.

#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

extern crate alloc;

mod blc;
mod field;
mod keygen;
mod mq;
mod params;
mod prg;
mod sign;
mod verify;
mod xof;

pub mod mqom2_l1_gf16_short_r5;
