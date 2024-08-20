use crate::annotations::AnnotationList;
use crate::config::{SdkInfo, StreamInfo};
use crate::errors::Result;
use crate::factories::new_annotator;
use crate::SdkAnnotator;
use alvarium_annotator::constants::{
    ACTION_CREATE, ACTION_MUTATE, ACTION_PUBLISH, ACTION_TRANSIT, ANNOTATION_SOURCE,
};
use alvarium_annotator::{MessageWrapper, Publisher};

pub struct SDK<'a, Pub: Publisher> {
    annotators: &'a mut [Box<SdkAnnotator>],
    pub cfg: SdkInfo,
    stream: Pub,
}

impl<'a, Pub: Publisher<StreamConfig = StreamInfo, Error = crate::errors::Error> + Send + Sync> SDK<'a, Pub> {
    pub async fn new(
        cfg: SdkInfo,
        annotators: &'a mut [Box<SdkAnnotator>],
    ) -> Result<SDK<'a, Pub>> {
        let mut publisher = Pub::new(&cfg.stream).await?;
        publisher.connect().await?;
        Ok(SDK {
            annotators,
            cfg,
            stream: publisher,
        })
    }

    pub async fn create(&mut self, data: &[u8]) -> Result<()> {
        let mut ann_list = AnnotationList::default();
        for annotator in self.annotators.iter_mut() {
            ann_list.items.push(annotator.execute(data)?);
        }

        let ann_bytes = serde_json::to_vec(&ann_list)?;
        let wrapper = MessageWrapper {
            action: ACTION_CREATE.clone(),
            message_type: std::any::type_name::<AnnotationList>(),
            content: &base64::encode(ann_bytes),
        };
        self.stream.publish(wrapper).await
    }

    pub async fn mutate(&mut self, old: &[u8], new: &[u8]) -> Result<()> {
        let mut ann_list = AnnotationList::default();

        let mut source = new_annotator(ANNOTATION_SOURCE.clone(), self.cfg.clone())?;
        let annotation = source.execute(old)?;
        ann_list.items.push(annotation);

        for annotator in self.annotators.iter_mut() {
            ann_list.items.push(annotator.execute(new)?);
        }

        let ann_bytes = serde_json::to_vec(&ann_list)?;
        let wrapper = MessageWrapper {
            action: ACTION_MUTATE.clone(),
            message_type: std::any::type_name::<AnnotationList>(),
            content: &base64::encode(ann_bytes),
        };
        self.stream.publish(wrapper).await
    }

    pub async fn transit(&mut self, data: &[u8]) -> Result<()> {
        let mut ann_list = AnnotationList::default();
        for annotator in self.annotators.iter_mut() {
            ann_list.items.push(annotator.execute(data)?);
        }

        let ann_bytes = serde_json::to_vec(&ann_list)?;
        let wrapper = MessageWrapper {
            action: ACTION_TRANSIT.clone(),
            message_type: std::any::type_name::<AnnotationList>(),
            content: &base64::encode(ann_bytes),
        };
        self.stream.publish(wrapper).await
    }

    pub async fn publish(&mut self, data: &[u8]) -> Result<()> {
        let mut ann_list = AnnotationList::default();
        for annotator in self.annotators.iter_mut() {
            ann_list.items.push(annotator.execute(data)?);
        }

        let ann_bytes = serde_json::to_vec(&ann_list)?;
        let wrapper = MessageWrapper {
            action: ACTION_PUBLISH.clone(),
            message_type: std::any::type_name::<AnnotationList>(),
            content: &base64::encode(ann_bytes),
        };
        self.stream.publish(wrapper).await
    }
}

#[cfg(test)]
mod sdk_tests {
    use super::SDK;
    use crate::factories::new_annotator;
    use crate::{
        config::{SdkInfo, Signable, StreamConfig},
        providers::stream_provider::DemiaPublisher,
        CONFIG_BYTES,
    };
    use alvarium_annotator::Publisher;
    use streams::{
        id::{Ed25519, PermissionDuration, Permissioned},
        transport::utangle::Client,
        User,
    };

    const BASE_TOPIC: &'static str = "Base Topic";

    #[tokio::test]
    async fn sdk_create_transit_publish() {
        // Uses base CONFIG_BYTES pulled from local config file (or the resources/test_config.json
        // if no config file is present)
        let sdk_info: SdkInfo = serde_json::from_slice(CONFIG_BYTES.as_slice()).unwrap();
        let publisher = mock_annotator(sdk_info.clone()).await;

        let mut annotators = Vec::new();
        for ann in &sdk_info.annotators {
            let annotator = new_annotator(ann.clone(), sdk_info.clone()).unwrap();
            annotators.push(annotator)
        }

        // Mocks SDK::new() without Pub::connect()
        let mut sdk = SDK {
            annotators: annotators.as_mut_slice(),
            cfg: sdk_info.clone(),
            stream: publisher,
        };

        let data = "A packet to send to subscribers".to_string();
        let sig = hex::encode([0u8; crypto::signatures::ed25519::Signature::LENGTH]);
        let signable = Signable::new(data, sig);
        sdk.create(signable.to_bytes().as_slice()).await.unwrap();
        sdk.transit(signable.to_bytes().as_slice()).await.unwrap();
        sdk.publish(signable.to_bytes().as_slice()).await.unwrap();
        std::fs::remove_file("temp_file").unwrap();
    }

    #[tokio::test]
    async fn sdk_mutate() {
        // Uses base CONFIG_BYTES pulled from local config file (or the resources/test_config.json
        // if no config file is present)
        let sdk_info: SdkInfo = serde_json::from_slice(CONFIG_BYTES.as_slice()).unwrap();
        let publisher = mock_annotator(sdk_info.clone()).await;

        let mut annotators = Vec::new();
        for ann in &sdk_info.annotators {
            let annotator = new_annotator(ann.clone(), sdk_info.clone()).unwrap();
            annotators.push(annotator)
        }

        // Mocks SDK::new() without Pub::connect()
        let mut sdk = SDK {
            annotators: annotators.as_mut_slice(),
            cfg: sdk_info.clone(),
            stream: publisher,
        };

        let data = "A packet to send to subscribers".to_string();
        let old_data = "Some old state of the data before mutation".to_string();
        let sig = hex::encode([0u8; crypto::signatures::ed25519::Signature::LENGTH]);
        let signable = Signable::new(data, sig);
        sdk.mutate(old_data.as_bytes(), signable.to_bytes().as_slice())
            .await
            .unwrap();
        std::fs::remove_file("temp_file").unwrap();
    }

    // Mocks Pub::new() with demiaPublisher Annotator
    async fn mock_annotator(sdk_info: SdkInfo) -> DemiaPublisher {
        if let StreamConfig::DemiaStreams(config) = &sdk_info.stream.config {
            let client: Client = Client::new(&config.tangle_node.uri());
            let mut seed = [0u8; 64];
            crypto::utils::rand::fill(&mut seed).unwrap();

            // Create an author to attach to
            let mut streams_author = User::builder()
                .with_transport(client)
                .with_identity(Ed25519::from_seed(seed))
                .build();
            let announcement = streams_author.create_stream(BASE_TOPIC).await.unwrap();

            let mut publisher = DemiaPublisher::new(&sdk_info.stream).await.unwrap();
            // To test connect, there needs to be a running provider (oracle) so we'll manually test
            // this part
            //annotator.connect().await.unwrap();

            // Annotator will receive the announcement and send a subscription, in connect() it would
            // send a subscription request to the oracle, for now we assume permission for connection
            publisher
                .client()
                .receive_message(announcement.address())
                .await
                .unwrap();
            let sub_message = publisher.client().subscribe().await.unwrap();

            // Streams author accepts the subscription and dedicates a new branch specifically for
            // the annotator
            streams_author
                .receive_message(sub_message.address())
                .await
                .unwrap();
            streams_author
                .new_branch(BASE_TOPIC, config.topic.as_str())
                .await
                .unwrap();
            streams_author
                .send_keyload(
                    config.topic.as_str(),
                    vec![Permissioned::ReadWrite(
                        publisher.identifier().clone(),
                        PermissionDuration::Perpetual,
                    )],
                    vec![],
                )
                .await
                .unwrap();

            publisher.await_keyload().await.unwrap();
            return publisher;
        } else {
            panic!("Test configuration is not correct, should be demiaStreams config")
        }
    }
}
