pub mod bitlocker;
pub mod envars;
pub mod memdump;
pub mod pslist;
pub mod triage;

use anyhow::Result;

use crate::api::{EnvarsRequest, MemdumpRequest, MemoryService, PsListRequest, TriageRequest};
use crate::bitlocker::BitlockerScanRequest;
use crate::cli::{Cli, Command};

pub fn run(cli: Cli) -> Result<()> {
    let service = MemoryService::new(cli.global.connector_options());
    let json = cli.global.json;

    match cli.command {
        Command::Pslist(args) => pslist::run(&service, PsListRequest { limit: args.limit }, json),
        Command::Envars(args) => envars::run(
            &service,
            EnvarsRequest {
                pid: args.pid,
                name: args.name,
            },
            json,
        ),
        Command::Memdump(args) => memdump::run(
            &service,
            MemdumpRequest {
                end: args.end,
                output: args.out,
                chunk_size: args.chunk_size,
            },
            json,
        ),
        Command::Triage(args) => triage::run(
            &service,
            TriageRequest {
                limit: args.limit,
                pid: args.pid,
            },
            json,
        ),
        Command::Bitlocker(args) => bitlocker::run(
            &service,
            BitlockerScanRequest {
                start: args.start,
                end: args.end,
                chunk_size: args.chunk_size,
            },
            json,
        ),
    }
}
