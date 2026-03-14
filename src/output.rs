use anyhow::{Context, Result};
use prettytable::{Cell, Row, Table, format};
use serde::Serialize;

pub fn print_json<T: Serialize>(value: &T) -> Result<()> {
    let json = serde_json::to_string_pretty(value).context("failed to serialize JSON output")?;
    println!("{json}");
    Ok(())
}

pub fn new_table(headers: &[&str]) -> Table {
    let mut table = Table::new();
    table.set_format(*format::consts::FORMAT_NO_LINESEP_WITH_TITLE);
    table.set_titles(Row::new(
        headers.iter().map(|header| Cell::new(header)).collect(),
    ));
    table
}

pub fn print_key_value_table(title: &str, rows: &[(&str, String)]) {
    println!("{title}");
    let mut table = new_table(&["Field", "Value"]);
    for (field, value) in rows {
        table.add_row(Row::new(vec![Cell::new(field), Cell::new(value)]));
    }
    table.printstd();
}
