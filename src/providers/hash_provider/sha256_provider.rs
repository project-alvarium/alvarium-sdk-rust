use alvarium_annotator::HashProvider;
use crypto::hashes::sha::{SHA256, SHA256_LEN};

#[derive(Default)]
pub struct Sha256Provider {}

impl Sha256Provider {
    pub fn new() -> Self {
        Sha256Provider::default()
    }
}

#[async_trait::async_trait]
impl HashProvider for Sha256Provider {
    async fn derive(&self, data: &[u8]) -> String {
        let mut digest = [0_u8; SHA256_LEN];
        SHA256(data, &mut digest);
        hex::encode(digest)
    }
}

#[test]
fn sha256_provider_test() {
    use log::info;
    struct Case<'a> {
        name: &'a str,
        data: &'a [u8],
        expected: &'a str,
    }

    let cases: Vec<Case> = vec![
        Case {
            name: "text variation 1",
            data: "foo".as_bytes(),
            expected: "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae",
        },
        Case {
            name: "text variation 2",
            data: "bar".as_bytes(),
            expected: "fcde2b2edba56bf408601fb721fe9b5c338d10ee429ea04fae5511b68fbf8fb9",
        },
        Case {
            name: "text variation 3",
            data: "baz".as_bytes(),
            expected: "baa5a0964d3320fbc0c6a922140453c8513ea24ab8fd0577034804a967248096",
        },
        Case {
            name: "byte sequence",
            data: &[1_u8, 2, 3, 4, 5, 6, 7, 8, 9, 0],
            expected: "9a89c68c4c5e28b8c4a5567673d462fff515db46116f9900624d09c474f593fb",
        },
    ];

    for case in cases {
        info!("Testing Case: {}", case.name);
        let hash_provider = Sha256Provider::new();
        let hash = hash_provider.derive(case.data);
        assert_eq!(case.expected, hash)
    }
}
