#![allow(clippy::new_ret_no_self)]
mod pki;
mod source;
mod tls;
mod tpm;

pub use pki::*;
pub use source::*;
pub use tls::*;
pub use tpm::*;


#[test]
fn unknown_annotator_failure() {
    let ann_type = alvarium_annotator::constants::AnnotationType::try_from("unknown");
    assert!(ann_type.is_err())
}