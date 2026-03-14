use anyhow::Result;

use crate::api::{MemdumpRequest, MemoryService};
use crate::output::{print_json, print_key_value_table};

pub fn run(service: &MemoryService, request: MemdumpRequest, json: bool) -> Result<()> {
    let report = service.memdump(&request)?;

    if json {
        return print_json(&report);
    }

    print_key_value_table(
        "dump complete",
        &[
            ("Dump start", format!("{:#x}", report.dump_start)),
            ("Dump end", format!("{:#x}", report.dump_end)),
            ("Bytes dumped", format!("{:#x}", report.bytes_dumped)),
            ("Output", report.output.display().to_string()),
        ],
    );
    Ok(())
}
