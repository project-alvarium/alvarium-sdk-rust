mod annotators;

pub use alvarium_annotator::{constants, Annotation, AnnotationList, Annotator};
pub use annotators::*;

pub fn mock_annotation() -> Annotation {
    let key = "The hash of the contents";
    let hash = constants::SHA256_HASH.clone();
    let host = "Host Device";
    let kind = constants::ANNOTATION_SOURCE.clone();
    let satisfied = true;

    Annotation::new(
        key,
        hash,
        host,
        constants::LAYER_APP.clone(),
        kind,
        satisfied,
        None,
    )
}
