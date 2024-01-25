# Alvarium Rust SDK

This is an implementation of the Alvarium SDK in Rust. It provides parity with the 
[go implementation](https://github.com/project-alvarium/alvarium-sdk-go).


Additionally, it implements the traits and core providers from the 
[alvarium-annotator](https://github.com/project-alvarium/alvarium-annotator) library, 
making up the core implementation.


## Usage
The first thing you will need to do is set up your configuration file. An example file can be
found [here](resources/test_config.json). You can copy this file and update with the appropriate
provider details. 

Examples of stream provider configurations can be found [here](resources/mqtt_stream_config.json) 
for mqtt and [here](resources/demia_streams_config.json) for a Demia (powered by IOTA) Streams provider.


To include the rust sdk in your project insert the following into your Cargo.toml file

```
[dependencies]
alvarium-annotator = { git = "https://github.com/project-alvarium/AlvariumAnnotator" }
alvarium-rust-sdk = { git = "https://github.com/project-alvarium/alvarium-rust-sdk" }
```

To use the sdk, you will also need to include an asynchronous runtime environment such as 
[tokio](https://github.com/tokio-rs/tokio). 

```
[dependencies]
tokio = "1.35.1"
```

Then you can get started using the sdk itself. 

```rust
// This is the main sdk implementation
use alvarium_rust_sdk::sdk::SDK; 
// You can use these factories to generate the core sdk annotators and signature providers
use alvarium_rust_sdk::factories::{new_annotator, new_signature_provider}; 
// This is where you will find configuration breakdowns for deserialisation
use alvarium_rust_sdk::config::{self, SdkInfo, StreamConfig};
// Here you can find network stream providers
use alvarium_rust_sdk::providers::stream_provider::{DemiaPublisher, MqttPublisher};


#[macro_use]
extern crate lazy_static;
extern crate core;
// Creates a static CONFIG_BYTES value from the ./config.json file if it exists
lazy_static! {
    pub static ref CONFIG_BYTES: Vec<u8> = {
        match std::fs::read("config/config.json") {
            Ok(config_bytes) => config_bytes,
            Err(_) => vec![]
        }
    };
}

#[tokio::main]
async fn main() {
    // Get configurations from the static configuration bytes
    let sdk_info: SdkInfo = serde_json::from_slice(CONFIG_BYTES.as_slice())?;
    // Prepare the signature provider
    let signature_provider = new_signature_provider( &sdk_info.signature)?;

    // Create a vector of annotators for the alvarium sdk instance
    let mut annotators: Vec<Box<dyn Annotator<Error = alvarium_rust_sdk::errors::Error> + '_>> = Vec::new();
    for ann in &sdk_info.annotators {
        // generate a new annotator from the sdk factory
        annotators.push(new_annotator(ann.clone(), sdk_info.clone())?);
    }

    // Create the alvarium SDK instance to annotate sensor data
    let mut sdk: SDK<'_, IotaPublisher> = SDK::new(sdk_info, annotators.as_mut_slice()).await?;

    // Source your data 
    let arbitrary_data = "Some data to send".as_bytes();

    // For PKI annotators, data should be wrapped in a Signable wrapper
    let sig = signature_provider.sign(&serde_json::to_vec(arbitrary_data)?)?;
    let data = Signable::new(serde_json::to_string(&arbitrary_data)?, sig);

    // New data creation annotation
    sdk.create(data.to_bytes().as_slice()).await?;
}
```



#### Custom Annotators 
Annotations are designed to provide universally accepted metadata for various interactions with data
along its lifecycle. Currently, there are 4 annotator types provided through the core sdk: 
Tpm confirmation, Tls usage confirmation, Source annotation, and Pki verification. These help to set a 
foundation of annotations that will be provided, but this does not serve all the possible annotatable 
use cases that one might need for an application/project. In order to accommodate that, the concept of an 
Annotator has been abstracted to an interface (trait), so that custom annotators can be developed and used 
within the Sdk.

An example implementation of this would be as follows 

```rust
use alvarium_annotator::{
    Annotation, Annotator, constants, derive_hash, serialise_and_sign,
    constants::AnnotationType,
};
use alvarium_rust_sdk::{
    config::{self, Signable}, 
    factories::{new_hash_provider, new_signature_provider}, 
    providers::sign_provider::SignatureProviderWrap
};

/// Defines a new annotator type that will implement the Annotator trait
pub struct ThresholdAnnotator {
    /// Hashing algorithm used for checksums
    hash: constants::HashType,
    /// Type of annotation (a wrapper around a string definition)
    kind: AnnotationType,
    /// Signature provider for signing data
    sign: SignatureProviderWrap,
    /// Threshold limits for custom annotation
    range: Range<u8>,
}

impl ThresholdAnnotator {
    pub fn new(cfg: &config::SdkInfo, range: Range<u8>) -> Result<impl Annotator<Error = alvarium_rust_sdk::errors::Error>> {
        Ok(ThresholdAnnotator {
            hash: cfg.hash.hash_type.clone(),
            kind: AnnotationType("threshold".to_string()),
            sign: new_signature_provider(&cfg.signature)?,
            range,
        })
    }

}

/// Implementation of the annotate() function for generating a threshold Annotation
impl Annotator for ThresholdAnnotator {
    type Error = alvarium_rust_sdk::errors::Error;
    fn annotate(&mut self, data: `&[u8]`) -> alvarium_rust_sdk::errors::Result<Annotation> {
        let hasher = new_hash_provider(&self.hash)?;
        let signable: Signable = serde_json::from_slice(data)?;
        let key = derive_hash(hasher, signable.seed.as_bytes());
        
        match gethostname::gethostname().to_str() {
            Some(host) => {
                let reading: std::result::Result<SensorReading, serde_json::Error> = serde_json::from_slice(data);
                let within_threshold = match reading {
                    Ok(reading) => {
                        let reading: SensorReading = serde_json::from_str(&signable.seed).unwrap();
                        reading.value <= self.range.end && reading.value >= self.range.start
                    },
                    Err(_) => false
                };

                let mut annotation = Annotation::new(&key, self.hash.clone(), host, self.kind.clone(), within_threshold);
                let signature = serialise_and_sign(&self.sign, &annotation)?;
                annotation.with_signature(&signature);
                Ok(annotation)
            },
            None => {
                Err(alvarium_rust_sdk::errors::Error::NoHostName.into())
            }
        }
    }
}
```

#### Custom Stream Providers
The base SDK includes an Mqtt and Demia Streams provider, but new stream providers can be created 
using the alvarium-annotator [Publisher](https://github.com/project-alvarium/alvarium-annotator/blob/main/src/providers.rs#L124)
trait. So long as this trait is implemented, any custom streaming layer provider will be compatible 
with the SDK.

You can see the localised implementations for the Mqtt and Demia providers [here](src/providers/stream_provider/mqtt.rs)
and [here](src/providers/stream_provider/demia.rs).


### API
The SDK provides a simple API for generating annotations dependent on the actions being taken.

NewSdk(), Create(), Mutate(), Transit(), Publish() and BootstrapHandler().

#### SDK::new()

```rust
pub async fn new(cfg: SdkInfo, annotators: &'a mut [Box<SdkAnnotator>]) -> crate::errors::Result<SDK<'a, Pub>>
```

Used to instantiate a new SDK instance with the specified list of annotators.

Takes a list of annotators, and a populated configuration. Returns an SDK instance.

#### Create()

```rust
    pub async fn create(&mut self, data: `&[u8]`) -> crate::errors::Result<()> 
```

Used to register creation of new data with the SDK. Passes data through the SDK instance's list of annotators.

##### Parameters
- data: `&[u8]` -- The data being handled represented as a byte array


#### Mutate()

```rust
pub async fn mutate(&mut self, old: &[u8], new: &[u8]) -> crate::errors::Result<()> 
```

Used to register mutation of existing data with the SDK. Passes data through the SDK instance's list of annotators.

##### Parameters
- old: &[u8] -- The source data item that is being modified, represented as a byte array
- new: &[u8] -- The new data item resulting from the change, represented as a byte array

Calling this method will link the old data to the new in a lineage. Specific annotations will be applied to the `new` data element.

#### Transit()

```rust
pub async fn transit(&mut self, data: `&[u8]`) -> crate::errors::Result<()>
```

Used to annotate data that is neither originated or modified but simply handed from one application to another.

##### Parameters
- data: `&[u8]` -- The data being handled represented as a byte array


#### Publish()

```rust
pub async fn publish(&mut self, data: `&[u8]`) -> crate::errors::Result<()>
```

Used to annotate data that is neither originated or modified but **before** being handed to another application.

##### Parameters
- data: `&[u8]` -- The data being handled represented as a byte array
