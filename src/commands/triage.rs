use anyhow::Result;
use prettytable::{Cell, Row};

use crate::api::{MemoryService, TriageRequest};
use crate::output::{new_table, print_json};

pub fn run(service: &MemoryService, request: TriageRequest, json: bool) -> Result<()> {
    let report = service.triage(&request)?;

    if json {
        return print_json(&report);
    }

    println!("triage: {} processes discovered", report.processes.len());
    let mut processes = new_table(&["PID", "NAME"]);
    for process in &report.processes {
        processes.add_row(Row::new(vec![
            Cell::new(&process.pid.to_string()),
            Cell::new(&process.name),
        ]));
    }
    processes.printstd();

    if let Some(selected) = report.selected_process {
        println!("modules for pid {} ({}):", selected.pid, selected.name);
        let mut modules = new_table(&["BASE", "NAME", "PATH"]);
        for module in selected.modules {
            modules.add_row(Row::new(vec![
                Cell::new(&format!("{:#x}", module.base)),
                Cell::new(&module.name),
                Cell::new(&module.path),
            ]));
        }
        modules.printstd();
    }

    Ok(())
}
