use std::sync::Arc;
use std::time::{Duration, SystemTime};

use crate::{event::EventMetadata, output::OutputDriver};
use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use chrono::DateTime;
use common::subscription::OtlpConfiguration;
use log::debug;
use opentelemetry::logs::{AnyValue, LogRecord, Logger, LoggerProvider as _, Severity};
use opentelemetry::InstrumentationScope;
use opentelemetry_otlp::{Compression, WithExportConfig, WithTonicConfig};
use opentelemetry_sdk::logs::{
    LogBatch, LogExporter as _, SdkLogRecord, SdkLogger, SdkLoggerProvider,
};
use opentelemetry_sdk::Resource;
use regex::Regex;

pub struct OutputOtlp {
    endpoint: String,
    exporter: opentelemetry_otlp::LogExporter,
    logger: SdkLogger,
    scope: InstrumentationScope,
    re_level: Regex,
    re_time: Regex,
    // Kept alive so that `logger` remains usable for the lifetime of this driver.
    _provider: SdkLoggerProvider,
}

impl OutputOtlp {
    pub fn new(config: &OtlpConfiguration) -> Result<Self> {
        let endpoint = config.endpoint().to_string();
        debug!("Initialize OTLP output with endpoint {}", endpoint);

        let resource = Resource::builder().with_service_name("openwec").build();

        let mut builder = opentelemetry_otlp::LogExporter::builder()
            .with_tonic()
            .with_endpoint(&endpoint);

        if let Some(timeout) = config.timeout() {
            builder = builder.with_timeout(Duration::from_secs(timeout));
        }

        if let Some(compression) = config.compression() {
            let compression = compression.parse::<Compression>().with_context(|| {
                format!(
                    "Invalid OTLP compression '{}' for endpoint {}",
                    compression, endpoint
                )
            })?;
            builder = builder.with_compression(compression);
        }

        let mut exporter = builder.build().with_context(|| {
            format!("Failed to build OTLP log exporter for endpoint {}", endpoint)
        })?;
        exporter.set_resource(&resource);

        let provider = SdkLoggerProvider::builder()
            .with_resource(resource)
            .build();
        let logger = provider.logger("openwec");
        let scope = InstrumentationScope::builder("openwec").build();

        let re_level = Regex::new(r"<Level>(\d+)</Level>").expect("valid Level regex");
        let re_time = Regex::new(r#"<TimeCreated[^>]*SystemTime=['\"]([^'\"]+)['\"]"#)
            .expect("valid TimeCreated regex");

        Ok(OutputOtlp {
            endpoint,
            exporter,
            logger,
            scope,
            re_level,
            re_time,
            _provider: provider,
        })
    }

    fn event_severity(&self, content: &str) -> (Severity, &'static str) {
        let level = self
            .re_level
            .captures(content)
            .and_then(|caps| caps.get(1))
            .and_then(|m| m.as_str().parse::<u8>().ok());
        match level {
            Some(1) => (Severity::Fatal, "CRITICAL"),
            Some(2) => (Severity::Error, "ERROR"),
            Some(3) => (Severity::Warn, "WARNING"),
            Some(4) => (Severity::Info, "INFORMATION"),
            Some(5) => (Severity::Debug, "VERBOSE"),
            _ => (Severity::Info, "INFORMATION"),
        }
    }

    fn event_timestamp(&self, content: &str) -> Option<SystemTime> {
        let raw = self.re_time.captures(content)?.get(1)?.as_str();
        let dt = DateTime::parse_from_rfc3339(raw).ok()?;
        Some(SystemTime::from(dt))
    }
}

#[async_trait]
impl OutputDriver for OutputOtlp {
    async fn write(
        &self,
        metadata: Arc<EventMetadata>,
        events: Arc<Vec<Arc<String>>>,
    ) -> Result<()> {
        if events.is_empty() {
            return Ok(());
        }

        let observed = SystemTime::from(metadata.time_received());

        let mut records: Vec<SdkLogRecord> = Vec::with_capacity(events.len());
        for event in events.iter() {
            let mut record = self.logger.create_log_record();
            let (severity, severity_text) = self.event_severity(event);
            record.set_timestamp(self.event_timestamp(event).unwrap_or(observed));
            record.set_observed_timestamp(observed);
            record.set_severity_number(severity);
            record.set_severity_text(severity_text);
            record.set_body(AnyValue::from(event.to_string()));
            record.add_attribute("subscription.name", metadata.subscription_name().to_string());
            record.add_attribute("subscription.uuid", metadata.subscription_uuid().to_string());
            record.add_attribute("client", metadata.client().to_string());
            record.add_attribute("client.address", metadata.addr().to_string());
            if let Some(node) = metadata.node_name() {
                record.add_attribute("node", node.to_string());
            }
            records.push(record);
        }

        let batch_data: Vec<(&SdkLogRecord, &InstrumentationScope)> =
            records.iter().map(|record| (record, &self.scope)).collect();
        let batch = LogBatch::new(&batch_data);

        self.exporter.export(batch).await.map_err(|err| {
            anyhow!(
                "Failed to export {} event(s) to OTLP endpoint {}: {}",
                events.len(),
                self.endpoint,
                err
            )
        })?;

        debug!(
            "Exported {} event(s) to OTLP endpoint {}",
            events.len(),
            self.endpoint
        );

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn driver() -> OutputOtlp {
        let config = OtlpConfiguration::new("http://localhost:4317".to_string(), None, None)
            .expect("valid OTLP configuration");
        OutputOtlp::new(&config).expect("driver should build")
    }

    #[tokio::test]
    async fn test_new_with_valid_config() {
        let config = OtlpConfiguration::new(
            "http://localhost:4317".to_string(),
            Some(30),
            Some("gzip".to_string()),
        )
        .expect("valid OTLP configuration");
        let output = OutputOtlp::new(&config).expect("driver should build");
        assert_eq!(output.endpoint, "http://localhost:4317");
    }

    #[tokio::test]
    async fn test_new_accepts_zstd_compression() {
        let config = OtlpConfiguration::new(
            "http://localhost:4317".to_string(),
            None,
            Some("zstd".to_string()),
        )
        .expect("valid OTLP configuration");
        assert!(OutputOtlp::new(&config).is_ok());
    }

    #[tokio::test]
    async fn test_event_severity_mapping() {
        let output = driver();

        assert_eq!(
            output.event_severity("<Level>1</Level>"),
            (Severity::Fatal, "CRITICAL")
        );
        assert_eq!(
            output.event_severity("<Level>2</Level>"),
            (Severity::Error, "ERROR")
        );
        assert_eq!(
            output.event_severity("<Level>3</Level>"),
            (Severity::Warn, "WARNING")
        );
        assert_eq!(
            output.event_severity("<Level>4</Level>"),
            (Severity::Info, "INFORMATION")
        );
        assert_eq!(
            output.event_severity("<Level>5</Level>"),
            (Severity::Debug, "VERBOSE")
        );
    }

    #[tokio::test]
    async fn test_event_severity_falls_back_to_info() {
        let output = driver();

        assert_eq!(
            output.event_severity("<Level>9</Level>"),
            (Severity::Info, "INFORMATION")
        );
        assert_eq!(
            output.event_severity("no level here"),
            (Severity::Info, "INFORMATION")
        );
        assert_eq!(
            output.event_severity("<Level>abc</Level>"),
            (Severity::Info, "INFORMATION")
        );
    }

    #[tokio::test]
    async fn test_event_timestamp_extraction() {
        let output = driver();

        let content = r#"<TimeCreated SystemTime="2024-01-02T03:04:05.123Z"/>"#;
        let expected = SystemTime::from(
            DateTime::parse_from_rfc3339("2024-01-02T03:04:05.123Z").unwrap(),
        );
        assert_eq!(output.event_timestamp(content), Some(expected));

        let content_single = r#"<TimeCreated SystemTime='2024-01-02T03:04:05.123Z'/>"#;
        assert_eq!(output.event_timestamp(content_single), Some(expected));
    }

    #[tokio::test]
    async fn test_event_timestamp_missing_or_invalid() {
        let output = driver();

        assert_eq!(output.event_timestamp("no timestamp here"), None);
        assert_eq!(
            output.event_timestamp(r#"<TimeCreated SystemTime="not-a-date"/>"#),
            None
        );
    }
}
