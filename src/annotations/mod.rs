mod annotators;

pub use annotators::*;
pub use alvarium_annotator::{Annotation, Annotator, AnnotationList, constants};

pub fn mock_annotation() -> Annotation {
    let key = "The hash of the contents";
    let hash = constants::SHA256_HASH.clone();
    let host = "Host Device";
    let kind = constants::ANNOTATION_SOURCE.clone();
    let satisfied = true;

    Annotation::new(key, hash, host, kind, satisfied)
}
