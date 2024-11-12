use alvarium_annotator::HashProvider;

#[derive(Default)]
pub struct NoneProvider {}

impl NoneProvider {
    pub fn new() -> Self {
        NoneProvider {}
    }
}

#[async_trait::async_trait]
impl HashProvider for NoneProvider {
    async fn derive(&self, data: &[u8]) -> String {
        unsafe { String::from_utf8_unchecked(data.to_vec()) }
    }
}

#[tokio::test]
async fn md5_provider_test() {
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
            expected: "foo",
        },
        Case {
            name: "text variation 2",
            data: "bar".as_bytes(),
            expected: "bar",
        },
        Case {
            name: "text variation 3",
            data: "baz".as_bytes(),
            expected: "baz",
        },
    ];

    for case in cases {
        info!("Testing Case: {}", case.name);
        let hash_provider = NoneProvider::new();
        let hash = hash_provider.derive(case.data).await;
        assert_eq!(case.expected, hash)
    }
}
