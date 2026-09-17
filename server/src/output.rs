use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use common::{
    settings::Outputs,
    subscription::{SubscriptionData, SubscriptionOutputDriver, SubscriptionOutputFormat},
};

use crate::{
    drivers::{
        files::{OutputFiles, OutputFilesContext},
        kafka::{OutputKafka, OutputKafkaContext},
        otlp::OutputOtlp,
        redis::OutputRedis,
        tcp::OutputTcp,
        unix::OutputUnixDatagram,
    },
    event::{EventData, EventMetadata},
    formats::{json::JsonFormat, nxlog::NxlogFormat, raw::RawFormat, raw_json::RawJsonFormat},
};

pub struct OutputDriversContext {
    settings: Outputs,
    files: Option<OutputFilesContext>,
    kafka: Option<OutputKafkaContext>,
}

impl OutputDriversContext {
    pub fn new(settings: &Outputs) -> Self {
        Self {
            settings: settings.clone(),
            files: None,
            kafka: None,
        }
    }

    pub fn initialize_missing(&mut self, subscriptions: &[SubscriptionData]) -> Result<()> {
        // Depending on the output drivers used and the settings, this function
        // initializes the required output contexts if not already done.
        // - It makes sure that the files context is initialized if at least one output uses the Files driver
        // - It makes sure that the kafka context is initialized if at least one output uses the Kafka driver
        //      AND one output did not configure kafka options (such as bootstrap.servers)

        if Self::need_files_context(subscriptions) && self.files.is_none() {
            self.files = Some(OutputFilesContext::new());
        }

        if Self::need_kafka_context(subscriptions) && self.kafka.is_none() {
            self.kafka = Some(OutputKafkaContext::new(self.settings.kafka())?);
        }

        Ok(())
    }

    fn need_files_context(subscriptions: &[SubscriptionData]) -> bool {
        for subscription in subscriptions {
            if subscription.is_active() {
                for output in subscription.outputs() {
                    if output.enabled() {
                        if let SubscriptionOutputDriver::Files(_) = output.driver() {
                            return true;
                        }
                    }
                }
            }
        }
        false
    }

    fn need_kafka_context(subscriptions: &[SubscriptionData]) -> bool {
        for subscription in subscriptions {
            if subscription.is_active() {
                for output in subscription.outputs() {
                    if let SubscriptionOutputDriver::Kafka(config) = output.driver() {
                        if output.enabled() && config.options().is_empty() {
                            return true;
                        }
                    }
                }
            }
        }
        false
    }

    pub fn clear(&mut self) {
        if let Some(files) = &mut self.files {
            files.clear();
        }
    }

    pub fn garbage_collect(&mut self, settings: &Outputs) -> Result<()> {
        if let Some(files) = &mut self.files {
            files.garbage_collect(settings.files().files_descriptor_close_timeout());
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct Output {
    format: SubscriptionOutputFormat,
    driver: Arc<dyn OutputDriver + Send + Sync>,
    // Only used for "describe()"
    subscription_output_driver: SubscriptionOutputDriver,
}

impl Output {
    pub fn new(
        format: &SubscriptionOutputFormat,
        driver: &SubscriptionOutputDriver,
        context: &mut OutputDriversContext,
    ) -> Result<Self> {
        let output_driver: Arc<dyn OutputDriver + Send + Sync> = match driver {
            SubscriptionOutputDriver::Files(config) => {
                Arc::new(OutputFiles::new(config, &context.files)?)
            }
            SubscriptionOutputDriver::Kafka(config) => {
                Arc::new(OutputKafka::new(config, &context.kafka)?)
            }
            SubscriptionOutputDriver::Tcp(config) => Arc::new(OutputTcp::new(config)?),
            SubscriptionOutputDriver::Redis(config) => Arc::new(OutputRedis::new(config)?),
            SubscriptionOutputDriver::UnixDatagram(config) => {
                Arc::new(OutputUnixDatagram::new(config)?)
            }
            SubscriptionOutputDriver::Otlp(config) => Arc::new(OutputOtlp::new(config)?),
        };

        Ok(Self {
            driver: output_driver,
            format: format.clone(),
            subscription_output_driver: driver.clone(),
        })
    }

    pub fn describe(&self) -> String {
        format!(
            "format: {:?}, driver: {:?}",
            self.format, self.subscription_output_driver
        )
    }

    pub fn driver(&self) -> String {
        format!("{:?}", self.subscription_output_driver)
    }

    pub async fn write(
        &self,
        metadata: Arc<EventMetadata>,
        events: Arc<Vec<Arc<String>>>,
    ) -> Result<()> {
        self.driver.write(metadata, events).await
    }

    pub fn format(&self) -> &SubscriptionOutputFormat {
        &self.format
    }
}

#[async_trait]
pub trait OutputDriver {
    /// Write a batch of events and associated metadata
    async fn write(
        &self,
        metadata: Arc<EventMetadata>,
        events: Arc<Vec<Arc<String>>>,
    ) -> Result<()>;
}

pub trait OutputFormat {
    /// Formats an event.
    /// If something wrong happens, formatter is allowed to return None.
    fn format(&self, metadata: &EventMetadata, data: &EventData) -> Option<Arc<String>>;
}

pub fn get_formatter(format: &SubscriptionOutputFormat) -> Box<dyn OutputFormat> {
    match format {
        SubscriptionOutputFormat::Json => Box::new(JsonFormat),
        SubscriptionOutputFormat::Raw => Box::new(RawFormat),
        SubscriptionOutputFormat::RawJson => Box::new(RawJsonFormat),
        SubscriptionOutputFormat::Nxlog => Box::new(NxlogFormat),
    }
}

#[cfg(test)]
mod tests {
    use std::{net::SocketAddr, str::FromStr, sync::Arc};

    use chrono::Utc;
    use common::{
        settings,
        subscription::{
            FilesConfiguration, SubscriptionData, SubscriptionOutput, SubscriptionOutputDriver,
            SubscriptionOutputFormat, SubscriptionUuid,
        },
    };
    use serde_json::Value;
    use uuid::Uuid;

    use crate::{
        event::{EventData, EventMetadata},
        output::{Output, OutputDriversContext},
        subscription::Subscription,
    };

    // Windows Security Event 4688 (Process Creation) — reused from individual format tests.
    const EVENT_4688: &str = r#"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}'/><EventID>4688</EventID><Version>2</Version><Level>0</Level><Task>13312</Task><Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime='2022-12-14T16:06:51.0643605Z'/><EventRecordID>114689</EventRecordID><Correlation/><Execution ProcessID='4' ThreadID='196'/><Channel>Security</Channel><Computer>win10.windomain.local</Computer><Security/></System><EventData><Data Name='SubjectUserSid'>S-1-5-18</Data><Data Name='SubjectUserName'>WIN10$</Data><Data Name='SubjectDomainName'>WINDOMAIN</Data><Data Name='SubjectLogonId'>0x3e7</Data><Data Name='NewProcessId'>0x3a8</Data><Data Name='NewProcessName'>C:\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe</Data><Data Name='TokenElevationType'>%%1936</Data><Data Name='ProcessId'>0x240</Data><Data Name='CommandLine'></Data><Data Name='TargetUserSid'>S-1-0-0</Data><Data Name='TargetUserName'>-</Data><Data Name='TargetDomainName'>-</Data><Data Name='TargetLogonId'>0x0</Data><Data Name='ParentProcessName'>C:\Windows\System32\services.exe</Data><Data Name='MandatoryLabel'>S-1-16-16384</Data></EventData><RenderingInfo Culture='en-US'><Message>A new process has been created.</Message><Level>Information</Level><Task>Process Creation</Task><Opcode>Info</Opcode><Channel>Security</Channel><Provider>Microsoft Windows security auditing.</Provider><Keywords><Keyword>Audit Success</Keyword></Keywords></RenderingInfo></Event>"#;

    // The sanitized client name written to the file path: '$' is stripped by sanitize_name.
    const CLIENT_SANITIZED: &str = "WIN10@WINDOMAIN.LOCAL";

    /// Build a Subscription and EventMetadata with fixed, reproducible values.
    fn make_subscription_and_metadata(
        output_context: &mut OutputDriversContext,
    ) -> (Subscription, EventMetadata) {
        let mut sub_data = SubscriptionData::new("Test", "");
        sub_data
            .set_uuid(SubscriptionUuid(
                Uuid::from_str("8B18D83D-2964-4F35-AC3B-6F4E6FFA727B").unwrap(),
            ))
            .set_uri(Some("/this/is/a/test".to_string()))
            .set_revision(Some("testrev".to_string()));

        let subscription = Subscription::from_data(sub_data, output_context).unwrap();

        let mut metadata = EventMetadata::new(
            &SocketAddr::from_str("192.168.58.100:5985").unwrap(),
            "WIN10$@WINDOMAIN.LOCAL",
            Some("openwec".to_owned()),
            &subscription,
            "188BB736-9441-5C66-188B-B73694415C66".to_string(),
            Some("rev1234".to_string()),
        );
        metadata.set_time_received(
            chrono::DateTime::parse_from_rfc3339("2022-12-14T17:07:03.331+01:00")
                .unwrap()
                .with_timezone(&Utc),
        );

        (subscription, metadata)
    }

    /// Create a SubscriptionData that has a single enabled Files output for the given format,
    /// pointing at `base_dir/{client}/events`. Used to trigger `initialize_missing` so that
    /// the `OutputFilesContext` background thread is started.
    fn sub_data_with_files_output(
        base_dir: &std::path::Path,
        format: SubscriptionOutputFormat,
    ) -> SubscriptionData {
        let path = format!("{}/{{}}/events", base_dir.display());
        let files_config = FilesConfiguration::new(path);
        let output = SubscriptionOutput::new(
            format,
            SubscriptionOutputDriver::Files(files_config),
            true,
        );
        let mut sub_data = SubscriptionData::new("TestOutput", "");
        sub_data.add_output(output);
        sub_data
    }

    /// Run the full format → Files-driver pipeline for one format and return the file contents.
    async fn run_pipeline(
        base_dir: &std::path::Path,
        format: SubscriptionOutputFormat,
    ) -> String {
        let mut output_context = OutputDriversContext::new(&settings::Outputs::default());

        // Force the Files background thread to be initialized.
        let init_sub = sub_data_with_files_output(base_dir, format.clone());
        output_context.initialize_missing(&[init_sub]).unwrap();

        let (subscription, metadata) = make_subscription_and_metadata(&mut output_context);
        let _ = subscription; // metadata borrows it internally via Arc

        // Build the Output (format + Files driver) through the public API.
        let files_config = FilesConfiguration::new(format!(
            "{}/{}/{{client}}/events",
            base_dir.display(),
            format!("{:?}", format).to_lowercase()
        ));
        let driver = SubscriptionOutputDriver::Files(files_config);
        let output = Output::new(&format, &driver, &mut output_context).unwrap();

        // Format the raw event.
        let formatter = super::get_formatter(&format);
        let event_data = EventData::new(Arc::new(EVENT_4688.to_string()), true);
        let formatted = formatter.format(&metadata, &event_data).expect("format should succeed");

        let metadata_arc = Arc::new(metadata);
        let events: Arc<Vec<Arc<String>>> = Arc::new(vec![formatted]);

        output.write(metadata_arc, events).await.unwrap();

        // Read back from the file the driver wrote.
        let file_path = base_dir
            .join(format!("{:?}", format).to_lowercase())
            .join(CLIENT_SANITIZED)
            .join("events");

        std::fs::read_to_string(&file_path)
            .unwrap_or_else(|e| panic!("failed to read {:?}: {}", file_path, e))
    }

    #[tokio::test]
    async fn test_pipeline_raw_format() {
        let tmp = tempfile::tempdir().unwrap();
        let content = run_pipeline(tmp.path(), SubscriptionOutputFormat::Raw).await;

        // Raw format writes the event XML verbatim, one event per line.
        assert_eq!(content, format!("{}\n", EVENT_4688));
    }

    #[tokio::test]
    async fn test_pipeline_raw_json_format() {
        let tmp = tempfile::tempdir().unwrap();
        let content = run_pipeline(tmp.path(), SubscriptionOutputFormat::RawJson).await;

        let line = content.trim_end_matches('\n');
        let json: Value = serde_json::from_str(line)
            .unwrap_or_else(|e| panic!("RawJson output is not valid JSON: {}\n---\n{}", e, line));

        // RawJson wraps the raw XML in a `data` field alongside subscription metadata.
        assert_eq!(json["data"].as_str().unwrap(), EVENT_4688);
        assert_eq!(json["meta"]["IpAddress"].as_str().unwrap(), "192.168.58.100");
        assert_eq!(
            json["meta"]["Principal"].as_str().unwrap(),
            "WIN10$@WINDOMAIN.LOCAL"
        );
        assert_eq!(json["meta"]["Node"].as_str().unwrap(), "openwec");
    }

    #[tokio::test]
    async fn test_pipeline_json_format() {
        let tmp = tempfile::tempdir().unwrap();
        let content = run_pipeline(tmp.path(), SubscriptionOutputFormat::Json).await;

        let line = content.trim_end_matches('\n');
        let json: Value = serde_json::from_str(line)
            .unwrap_or_else(|e| panic!("Json output is not valid JSON: {}\n---\n{}", e, line));

        assert_eq!(json["System"]["EventID"].as_u64().unwrap(), 4688);
        assert_eq!(
            json["System"]["Channel"].as_str().unwrap(),
            "Security"
        );
        assert_eq!(
            json["System"]["Computer"].as_str().unwrap(),
            "win10.windomain.local"
        );
        // Subscription metadata is embedded in the OpenWEC field.
        assert_eq!(json["OpenWEC"]["IpAddress"].as_str().unwrap(), "192.168.58.100");
    }

    #[tokio::test]
    async fn test_pipeline_nxlog_format() {
        let tmp = tempfile::tempdir().unwrap();
        let content = run_pipeline(tmp.path(), SubscriptionOutputFormat::Nxlog).await;

        let line = content.trim_end_matches('\n');
        let json: Value = serde_json::from_str(line)
            .unwrap_or_else(|e| panic!("Nxlog output is not valid JSON: {}\n---\n{}", e, line));

        // Nxlog format flattens event fields; EventID is a top-level integer.
        assert_eq!(json["EventID"].as_u64().unwrap(), 4688);
        assert_eq!(json["Channel"].as_str().unwrap(), "Security");
        assert_eq!(json["Hostname"].as_str().unwrap(), "win10.windomain.local");
        assert_eq!(json["OpenWEC"]["IpAddress"].as_str().unwrap(), "192.168.58.100");
    }

    #[tokio::test]
    async fn test_pipeline_multiple_events_in_batch() {
        let tmp = tempfile::tempdir().unwrap();
        let mut output_context = OutputDriversContext::new(&settings::Outputs::default());

        let format = SubscriptionOutputFormat::Raw;
        let init_sub = sub_data_with_files_output(tmp.path(), format.clone());
        output_context.initialize_missing(&[init_sub]).unwrap();

        let (_, metadata) = make_subscription_and_metadata(&mut output_context);

        let files_config = FilesConfiguration::new(format!(
            "{}/batch/{{client}}/events",
            tmp.path().display()
        ));
        let driver = SubscriptionOutputDriver::Files(files_config);
        let output = Output::new(&format, &driver, &mut output_context).unwrap();

        // Write a batch of 3 identical events.
        let formatted = Arc::new(EVENT_4688.to_string());
        let events: Arc<Vec<Arc<String>>> =
            Arc::new(vec![formatted.clone(), formatted.clone(), formatted]);

        output.write(Arc::new(metadata), events).await.unwrap();

        let file_path = tmp.path().join("batch").join(CLIENT_SANITIZED).join("events");
        let content = std::fs::read_to_string(&file_path).unwrap();

        // Each event is written on its own line.
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 3, "expected 3 events in file, got {}", lines.len());
        for line in &lines {
            assert_eq!(*line, EVENT_4688);
        }
    }
}
