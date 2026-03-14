use anyhow::Result;
use clap::Parser;
use exhume_memory::{Cli, run, runtime};

fn main() -> Result<()> {
    let cli = Cli::parse();
    runtime::init_logging(cli.global.log_level);
    runtime::configure_runtime_paths();
    run(cli)
}
