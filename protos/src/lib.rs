pub mod attestation {
    #![allow(clippy::all)]
    #![allow(dead_code)]
    #![allow(missing_docs)]
    #![allow(non_camel_case_types)]
    #![allow(non_snake_case)]
    #![allow(non_upper_case_globals)]
    #![allow(unused_attributes)]
    #![allow(unused_mut)]
    #![allow(unused_results)]
    include!(concat!(env!("OUT_DIR"), "/protos/attestation_sanitized.rs"));
}
pub use attestation::*;
