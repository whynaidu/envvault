mod global;
mod settings;

pub use global::GlobalConfig;
pub use settings::{
    validate_env_against_config, AuditSettings, CustomPattern, SecretScanningSettings, Settings,
};
