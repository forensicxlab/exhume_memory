use anyhow::Result;
use prettytable::{Cell, Row};

use crate::api::{EnvarsRequest, MemoryService};
use crate::output::{new_table, print_json, print_key_value_table};

pub fn run(service: &MemoryService, request: EnvarsRequest, json: bool) -> Result<()> {
    let report = service.envars(&request)?;

    if json {
        return print_json(&report);
    }

    print_key_value_table(
        "environment variables",
        &[
            ("PID", report.pid.to_string()),
            ("Process", report.process_name.clone()),
            ("Variables", report.variables.len().to_string()),
        ],
    );

    let mut table = new_table(&["NAME", "VALUE", "ARCH", "ADDRESS"]);
    for variable in report.variables {
        table.add_row(Row::new(vec![
            Cell::new(&variable.name),
            Cell::new(&variable.value),
            Cell::new(&variable.arch),
            Cell::new(&format!("{:#x}", variable.address)),
        ]));
    }
    table.printstd();

    Ok(())
}
