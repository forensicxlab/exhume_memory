use anyhow::Result;
use prettytable::{Cell, Row};

use crate::api::MemoryService;
use crate::bitlocker::BitlockerScanRequest;
use crate::output::{new_table, print_json, print_key_value_table};

pub fn run(service: &MemoryService, request: BitlockerScanRequest, json: bool) -> Result<()> {
    let report = service.scan_bitlocker(&request)?;

    if json {
        return print_json(&report);
    }

    print_key_value_table(
        "searching for BitLocker material...",
        &[
            ("Scan start", format!("{:#x}", report.scan_start)),
            ("Scan end", format!("{:#x}", report.scan_end)),
            (
                "Scan size",
                format!(
                    "{:.2} GiB",
                    (report.scan_end.saturating_sub(report.scan_start)) as f64
                        / (1024.0 * 1024.0 * 1024.0)
                ),
            ),
            ("Total chunks", report.chunk_count.to_string()),
        ],
    );

    if report.hits.is_empty() {
        println!("no BitLocker material found");
        return Ok(());
    }

    let mut hits = new_table(&["ADDRESS", "TAG", "TYPE", "FVEK", "TWEAK", "FULL"]);
    for hit in report.hits {
        hits.add_row(Row::new(vec![
            Cell::new(&format!("{:#x}", hit.address)),
            Cell::new(&hit.tag),
            Cell::new(&format!("{:?}", hit.material.material_type)),
            Cell::new(&hex::encode(&hit.material.fvek)),
            Cell::new(
                &hit.material
                    .tweak
                    .as_ref()
                    .map(hex::encode)
                    .unwrap_or_else(|| "-".to_string()),
            ),
            Cell::new(&hit.material.render_full_key_hex()),
        ]));
    }
    hits.printstd();

    Ok(())
}
