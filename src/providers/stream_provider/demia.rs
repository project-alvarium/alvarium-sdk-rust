use crate::config::{DemiaStreamsConfig, StreamConfig, StreamInfo};
use alvarium_annotator::{MessageWrapper, Publisher};
use streams::{Address, User, transport::utangle::Client, id::{Ed25519, Identifier}, Message};
use core::str::FromStr;
use std::thread::sleep;
use std::time::Duration;
use serde::{Serialize, Deserialize};
use futures::TryStreamExt;
use log::{debug, info};
use crate::errors::{Error, Result};

const MAX_RETRIES: u8 = 100;


pub struct DemiaPublisher {
    cfg: DemiaStreamsConfig,
    user: User<Client>,
    identifier: Identifier,
}


impl DemiaPublisher {
    pub(crate) async fn await_keyload(&mut self) -> Result<()> {
        let mut i = 0;
        info!("Awaiting Keyload message from publisher");
        while i < MAX_RETRIES {
            let m = self.user.messages();
            if let Ok(next_messages) = m.try_collect::<Vec<Message>>().await {
                for message in next_messages {
                    debug!("Found message: {}", message.address);
                    if let Some(keyload) = message.as_keyload() {
                        debug!("Found keyload");
                        if keyload.includes_subscriber(&self.identifier) {
                            return Ok(())
                        }
                    }
                }
            }
            sleep(Duration::from_secs(5));
            i += 1;
        }
        Err(Error::StreamsKeyloadNotFound)
    }

    pub fn client(&mut self) -> &mut User<Client> {
        &mut self.user
    }

    pub fn identifier(&self) -> &Identifier {
        &self.identifier
    }
}

#[async_trait::async_trait]
impl Publisher for DemiaPublisher {
    type StreamConfig = StreamInfo;
    type Error = crate::errors::Error;
    async fn new(cfg: &StreamInfo) -> Result<DemiaPublisher> {
        match &cfg.config {
            StreamConfig::DemiaStreams(cfg) => {
                let client = Client::new(cfg.tangle_node.uri());
                match std::fs::read(&cfg.backup.path) {
                    Ok(user_bytes) => {
                        let user = User::restore(user_bytes, &cfg.backup.password, client).await?;
                        let identifier = user.identifier().unwrap().clone();
                        Ok(
                            DemiaPublisher {
                                cfg: cfg.clone(),
                                user,
                                identifier
                            }
                        )
                    },
                    Err(_) => {
                        let mut seed = [0u8; 64];
                        crypto::utils::rand::fill(&mut seed).unwrap();

                        let user = User::builder()
                            .with_transport(client)
                            .with_identity(Ed25519::from_seed(seed))
                            .lean()
                            .build();

                        let identifier = user.identifier().unwrap().clone();
                        Ok(
                            DemiaPublisher {
                                cfg: cfg.clone(),
                                user,
                                identifier,
                            }
                        )
                    }
                }
            },
            _ => Err(Error::IncorrectConfig)
        }
    }

    async fn close(&mut self) -> Result<()> {
        // No need to disconnect from stream or drop anything
        Ok(())
    }

    async fn reconnect(&mut self) -> Result<()> {
        // No need to reconnect as disconnection does not occur
        Ok(())
    }
    async fn connect(&mut self) -> Result<()> {
        if self.user.stream_address().is_none() {
            let announcement = get_announcement_id(&self.cfg.provider.uri()).await?;
            let announcement_address = Address::from_str(&announcement)?;
            info!("Announcement address: {}", announcement_address.to_string());

            debug!("Fetching announcement message");
            self.user.receive_message(announcement_address).await?;

            debug!("Sending Streams Subscription message");
            let subscription = self.user.subscribe().await?;

            #[cfg(feature = "did-streams")]
                let id_type = 1;
            #[cfg(not(feature = "did-streams"))]
                let id_type = 0;

            let body = SubscriptionRequest {
                address: subscription.address().to_string(),
                identifier: self.identifier.to_string(),
                id_type,
                topic: self.cfg.topic.to_string(),
            };

            let body_bytes = serde_json::to_vec(&body)?;

            info!("Sending subscription request to console");
            send_subscription_request(&self.cfg.provider.uri(), body_bytes).await?;
            self.await_keyload().await?;
        }
        Ok(())
    }

    async fn publish(&mut self, msg: MessageWrapper<'_>) -> Result<()> {
        debug!("Publishing message: {:?}", msg);
        let bytes = serde_json::to_vec(&msg)?;

        let packet = self.user.message()
            .with_payload(bytes)
            .with_topic(self.cfg.topic.as_str())
            .signed()
            .send()
            .await?;

        let backup = self.user.backup(&self.cfg.backup.password).await?;
        std::fs::write(&self.cfg.backup.path, backup).map_err(Error::BackupFailed)?;
        info!("Published new message: {}", packet.address());
        Ok(())
    }
}

async fn get_announcement_id(uri: &str) -> Result<String> {
    #[derive(Serialize, Deserialize)]
    struct AnnouncementResponse {
        announcement_id: String
    }

    info!("Fetching stream announcement id");
    let client = reqwest::Client::new();
    let response = client.get(uri.to_owned() + "/get_announcement_id")
        .send()
        .await?
        .bytes()
        .await?;

    let announcement: AnnouncementResponse = serde_json::from_slice(&response)?;
    Ok(announcement.announcement_id)
}


#[derive(Serialize, Deserialize)]
struct SubscriptionRequest {
    address: String,
    identifier: String,
    #[serde(rename="idType")]
    id_type: u8,
    topic: String,
}
async fn send_subscription_request(uri: &str, body: Vec<u8>) -> Result<()> {
    reqwest::Client::new()
        .post(uri.to_owned() + "/subscribe")
        .body(body)
        .header("Content-Type", "application/json")
        .send()
        .await?;
    Ok(())
}



#[cfg(test)]
mod demia_test {
    use log::info;
    use crate::{
        annotations::{AnnotationList, Annotator, PkiAnnotator},
        config::{SdkInfo, StreamConfig, Signable}
    };
    use streams::id::{PermissionDuration, Permissioned};
    use super::{Client, DemiaPublisher, Ed25519, Publisher, MessageWrapper, User};
    const BASE_TOPIC: &'static str = "Base Topic";

    #[tokio::test]
    async fn new_demia_streams_provider() {
        let sdk_info: SdkInfo = serde_json::from_slice(crate::CONFIG_BYTES.as_slice()).unwrap();
        let _annotator = mock_provider(sdk_info).await;
    }

    #[tokio::test]
    async fn streams_provider_publish() {
        let sdk_info: SdkInfo = serde_json::from_slice(crate::CONFIG_BYTES.as_slice()).unwrap();
        let mut publisher = mock_provider(sdk_info.clone()).await;

        let raw_data_msg = "A packet to send to subscribers".to_string();
        let sig = hex::encode([0u8; crypto::signatures::ed25519::SIGNATURE_LENGTH]);
        let signable = Signable::new(raw_data_msg, sig);

        let mut list = AnnotationList { items: vec![] };
        let mut pki_annotator = PkiAnnotator::new(&sdk_info).unwrap();
        list.items.push(
            pki_annotator.annotate(
                &serde_json::to_vec(&signable).unwrap()
            ).unwrap()
        );

        let data = MessageWrapper {
            action: crate::annotations::constants::ACTION_CREATE.clone(),
            message_type: std::any::type_name::<AnnotationList>(),
            content: &base64::encode(&serde_json::to_vec(&list).unwrap()),
        };

        info!("Publishing...");
        publisher.publish(data).await.unwrap();
        std::fs::remove_file("temp_file").unwrap();
    }

    #[tokio::test]
    async fn streams_provider_restore() {
        let sdk_info: SdkInfo = serde_json::from_slice(crate::CONFIG_BYTES.as_slice()).unwrap();
        let mut provider = mock_provider(sdk_info.clone()).await;
        let backup = provider.user.backup("password").await.unwrap();
        std::fs::write("temp_file", backup).unwrap();
        // If it made it here it's already confirmed that this is the case
        if let StreamConfig::DemiaStreams(_config) = &sdk_info.stream.config {
            // If no backup is available, then the restored publisher will have a new identity
            let restored = DemiaPublisher::new(&sdk_info.stream).await.unwrap();
            assert!(restored.identifier.eq(provider.identifier()));
            std::fs::remove_file("temp_file").unwrap();
        }
    }

    async fn mock_provider(sdk_info: SdkInfo) -> DemiaPublisher {
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

            let mut annotator = DemiaPublisher::new(&sdk_info.stream).await.unwrap();
            // To test connect, there needs to be a running provider (oracle) so we'll manually test
            // this part
            //annotator.connect().await.unwrap();

            // Annotator will receive the announcement and send a subscription, in connect() it would
            // send a subscription request to the oracle, for now we assume permission for connection
            annotator.client().receive_message(announcement.address()).await.unwrap();
            let sub_message = annotator.client().subscribe().await.unwrap();

            // Streams author accepts the subscription and dedicates a new branch specifically for
            // the annotator
            streams_author.receive_message(sub_message.address()).await.unwrap();
            streams_author.new_branch(BASE_TOPIC, config.topic.as_str()).await.unwrap();
            streams_author.send_keyload(
                config.topic.as_str(),
                vec![Permissioned::ReadWrite(annotator.identifier().clone(), PermissionDuration::Perpetual)],
                vec![]
            )
                .await
                .unwrap();

            annotator.await_keyload().await.unwrap();
            return annotator
        } else {
            panic!("Test configuration is not correct, should be demiaStreams config")
        }
    }
}



