pub mod api;
pub mod bitlocker;
pub mod cli;
pub mod commands;
pub mod connector;
pub mod output;
pub mod runtime;

pub use api::{
    EnvarRecord, EnvarsReport, EnvarsRequest, MemdumpCallbacks, MemdumpReport, MemdumpRequest,
    MemoryProgressUpdate, MemoryService, ModuleRecord, ProbeReport, ProcessRecord, ProcessTriage,
    PsListReport, PsListRequest, TriageReport, TriageRequest,
};
pub use bitlocker::{
    BitlockerHit, BitlockerScanCallbacks, BitlockerScanReport, BitlockerScanRequest, FveMaterial,
    MaterialType, scan_bitlocker, scan_bitlocker_with_callbacks,
};
pub use cli::{
    BitlockerArgs, Cli, Command, ConnectorKind, EnvarsArgs, GlobalArgs, LogLevel, MemdumpArgs,
    PsListArgs, TriageArgs,
};
pub use connector::{Connector, ConnectorOptions};

use anyhow::Result;

pub fn run(cli: Cli) -> Result<()> {
    commands::run(cli)
}
