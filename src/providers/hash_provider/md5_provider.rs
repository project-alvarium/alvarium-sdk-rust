use alvarium_annotator::HashProvider;
use md5_rs::Context;

#[derive(Default)]
pub struct MD5Provider {}

impl MD5Provider {
    pub fn new() -> Self {
        MD5Provider::default()
    }
}

impl HashProvider for MD5Provider {
    fn derive(&self, data: &[u8]) -> String {
        let mut ctx = Context::new();
        ctx.read(data);
        hex::encode(ctx.finish())
    }
}

#[test]
fn md5_provider_test() {
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
            expected: "acbd18db4cc2f85cedef654fccc4a4d8",
        },
        Case {
            name: "text variation 2",
            data: "bar".as_bytes(),
            expected: "37b51d194a7513e45b56f6524f2d51f2",
        },
        Case {
            name: "text variation 3",
            data: "baz".as_bytes(),
            expected: "73feffa4b7f6bb68e44cf984c85f6e88",
        },
        Case {
            name: "byte sequence",
            data: &[1_u8, 2, 3, 4, 5, 6, 7, 8, 9, 0],
            expected: "7f63cb6d067972c3f34f094bb7e776a8",
        },
    ];

    let hash_provider = MD5Provider::new();
    for case in cases {
        info!("Testing Case: {}", case.name);
        let hash = hash_provider.derive(case.data);
        assert_eq!(case.expected, hash)
    }
}
