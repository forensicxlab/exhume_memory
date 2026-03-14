use anyhow::Result;
use prettytable::{Cell, Row};

use crate::api::{MemoryService, PsListRequest};
use crate::output::{new_table, print_json};

pub fn run(service: &MemoryService, request: PsListRequest, json: bool) -> Result<()> {
    let report = service.pslist(&request)?;

    if json {
        return print_json(&report);
    }

    let mut table = new_table(&["PID", "SYS ARCH", "PROC ARCH", "NAME"]);
    for process in report.processes {
        table.add_row(Row::new(vec![
            Cell::new(&process.pid.to_string()),
            Cell::new(&process.sys_arch.to_string()),
            Cell::new(&process.proc_arch.to_string()),
            Cell::new(&process.name),
        ]));
    }
    table.printstd();

    Ok(())
}
