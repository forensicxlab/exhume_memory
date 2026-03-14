use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

use crate::connector::ConnectorOptions;

#[derive(Parser, Debug, Clone)]
#[command(name = "exhume_memory")]
#[command(
    about = "Exhume volatile memory through reusable forensic workflows.",
    subcommand_required = true,
    arg_required_else_help = true
)]
pub struct Cli {
    #[command(flatten)]
    pub global: GlobalArgs,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Args, Debug, Clone)]
pub struct GlobalArgs {
    /// Connector args, e.g. ':device=FPGA' for pcileech or '/path/to/dump' for rawmem.
    #[arg(long, global = true, default_value = ":device=FPGA")]
    pub connector: String,

    /// Connector type to use.
    #[arg(long, global = true, value_enum, default_value_t = ConnectorKind::Pcileech)]
    pub connector_type: ConnectorKind,

    /// Logging verbosity.
    #[arg(long, global = true, value_enum, default_value_t = LogLevel::Info)]
    pub log_level: LogLevel,

    /// Emit structured JSON on stdout instead of human-readable text.
    #[arg(long, global = true)]
    pub json: bool,
}

impl GlobalArgs {
    pub fn connector_options(&self) -> ConnectorOptions {
        ConnectorOptions {
            connector: self.connector.clone(),
            kind: self.connector_type,
        }
    }
}

#[derive(Subcommand, Debug, Clone)]
pub enum Command {
    /// List processes seen in the memory source.
    Pslist(PsListArgs),
    /// List environment variables for a process.
    Envars(EnvarsArgs),
    /// Dump a physical memory range to a file.
    Memdump(MemdumpArgs),
    /// Print high-level triage data and optional module listing for a PID.
    Triage(TriageArgs),
    /// Scan the memory source for BitLocker material.
    Bitlocker(BitlockerArgs),
}

#[derive(Args, Debug, Clone)]
pub struct PsListArgs {
    /// Process listing limit.
    #[arg(long, default_value_t = 25)]
    pub limit: usize,
}

#[derive(Args, Debug, Clone)]
pub struct EnvarsArgs {
    /// PID to inspect.
    #[arg(long)]
    pub pid: u32,

    /// Optional environment variable name filter (case-sensitive).
    #[arg(long)]
    pub name: Option<String>,
}

#[derive(Args, Debug, Clone)]
pub struct MemdumpArgs {
    /// End physical address for memdump (exclusive). Defaults to the connector max address.
    #[arg(long, value_parser = parse_u64)]
    pub end: Option<u64>,

    /// Output file path for memdump.
    #[arg(long)]
    pub out: PathBuf,

    /// Read chunk size in bytes for memdump.
    #[arg(long, default_value_t = 0x100000, value_parser = parse_usize)]
    pub chunk_size: usize,
}

#[derive(Args, Debug, Clone)]
pub struct TriageArgs {
    /// Optional PID for triage module to print modules.
    #[arg(long)]
    pub pid: Option<u32>,

    /// Process listing limit for pslist/triage.
    #[arg(long, default_value_t = 25)]
    pub limit: usize,
}

#[derive(Args, Debug, Clone)]
pub struct BitlockerArgs {
    /// Start physical address for scan (inclusive).
    #[arg(long, value_parser = parse_u64)]
    pub start: Option<u64>,

    /// End physical address for scan (exclusive).
    #[arg(long, value_parser = parse_u64)]
    pub end: Option<u64>,

    /// Read chunk size in bytes for the scan.
    #[arg(long, default_value_t = 0x100000, value_parser = parse_usize)]
    pub chunk_size: usize,
}

#[derive(Copy, Clone, Debug, ValueEnum, Eq, PartialEq)]
pub enum ConnectorKind {
    Pcileech,
    Rawmem,
}

#[derive(Copy, Clone, Debug, ValueEnum, Eq, PartialEq)]
pub enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

pub fn parse_u64(s: &str) -> std::result::Result<u64, String> {
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).map_err(|e| e.to_string())
    } else {
        s.parse::<u64>().map_err(|e| e.to_string())
    }
}

pub fn parse_usize(s: &str) -> std::result::Result<usize, String> {
    parse_u64(s).and_then(|v| usize::try_from(v).map_err(|e| e.to_string()))
}
