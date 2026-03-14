use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use memflow::mem::phys_mem::PhysicalMemory;
use memflow::prelude::v1::*;
use memflow_win32::prelude::v1::*;
use serde::Serialize;

use crate::bitlocker::{BitlockerScanReport, BitlockerScanRequest, scan_bitlocker};
use crate::connector::{Connector, ConnectorOptions};

#[derive(Debug, Clone)]
pub struct PsListRequest {
    pub limit: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProcessRecord {
    pub pid: u32,
    pub sys_arch: String,
    pub proc_arch: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct PsListReport {
    pub processes: Vec<ProcessRecord>,
}

#[derive(Debug, Clone)]
pub struct TriageRequest {
    pub limit: usize,
    pub pid: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct EnvarsRequest {
    pub pid: u32,
    pub name: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ModuleRecord {
    pub base: u64,
    pub name: String,
    pub path: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProcessTriage {
    pub pid: u32,
    pub name: String,
    pub modules: Vec<ModuleRecord>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TriageReport {
    pub processes: Vec<ProcessRecord>,
    pub selected_process: Option<ProcessTriage>,
}

#[derive(Debug, Clone, Serialize)]
pub struct EnvarRecord {
    pub name: String,
    pub value: String,
    pub address: u64,
    pub arch: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct EnvarsReport {
    pub pid: u32,
    pub process_name: String,
    pub variables: Vec<EnvarRecord>,
}

#[derive(Debug, Clone)]
pub struct MemdumpRequest {
    pub end: Option<u64>,
    pub output: PathBuf,
    pub chunk_size: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct MemdumpReport {
    pub dump_start: u64,
    pub dump_end: u64,
    pub bytes_dumped: u64,
    pub output: PathBuf,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProbeReport {
    pub max_address: u64,
    pub physical_memory_end: u64,
    pub processes: Vec<ProcessRecord>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MemoryProgressUpdate {
    pub current: u64,
    pub total: u64,
    pub message: String,
}

pub type ProgressCallback = Arc<dyn Fn(MemoryProgressUpdate) + Send + Sync + 'static>;

#[derive(Clone, Default)]
pub struct MemdumpCallbacks {
    pub on_progress: Option<ProgressCallback>,
}

#[derive(Debug, Clone)]
pub struct MemoryService {
    connector_options: ConnectorOptions,
}

impl MemoryService {
    pub fn new(connector_options: ConnectorOptions) -> Self {
        Self { connector_options }
    }

    pub fn connector_options(&self) -> &ConnectorOptions {
        &self.connector_options
    }

    pub fn open_connector(&self) -> Result<Connector> {
        self.connector_options.open()
    }

    pub fn probe(&self, request: &PsListRequest) -> Result<ProbeReport> {
        let connector = self.open_connector()?;
        let max_address = connector.metadata().max_address.to_umem();
        let mut os = Win32Kernel::builder(connector)
            .build_default_caches()
            .build()
            .context("failed to initialize win32 OS layer")?;

        let kernel_last = os.phys_view().metadata().max_address.to_umem();
        let physical_memory_end = max_address.max(kernel_last).saturating_add(1);
        let processes = os
            .process_info_list()
            .context("unable to read process list from target")?
            .into_iter()
            .take(request.limit)
            .map(|p| ProcessRecord {
                pid: p.pid,
                sys_arch: p.sys_arch.to_string(),
                proc_arch: p.proc_arch.to_string(),
                name: p.name.to_string(),
            })
            .collect();

        Ok(ProbeReport {
            max_address,
            physical_memory_end,
            processes,
        })
    }

    pub fn pslist(&self, request: &PsListRequest) -> Result<PsListReport> {
        let connector = self.open_connector()?;
        let mut os = Win32Kernel::builder(connector)
            .build_default_caches()
            .build()
            .context("failed to initialize win32 OS layer")?;

        let processes = os
            .process_info_list()
            .context("unable to read process list from target")?
            .into_iter()
            .take(request.limit)
            .map(|p| ProcessRecord {
                pid: p.pid,
                sys_arch: p.sys_arch.to_string(),
                proc_arch: p.proc_arch.to_string(),
                name: p.name.to_string(),
            })
            .collect();

        Ok(PsListReport { processes })
    }

    pub fn triage(&self, request: &TriageRequest) -> Result<TriageReport> {
        let connector = self.open_connector()?;
        let mut os = Win32Kernel::builder(connector)
            .build_default_caches()
            .build()
            .context("failed to initialize win32 OS layer")?;

        let process_list = os
            .process_info_list()
            .context("unable to read process list from target")?;

        let processes = process_list
            .iter()
            .take(request.limit)
            .map(|p| ProcessRecord {
                pid: p.pid,
                sys_arch: p.sys_arch.to_string(),
                proc_arch: p.proc_arch.to_string(),
                name: p.name.to_string(),
            })
            .collect();

        let selected_process = if let Some(pid) = request.pid {
            let proc_info = process_list
                .into_iter()
                .find(|p| p.pid == pid)
                .with_context(|| format!("process not found in list: pid={pid}"))?;
            let resolved_name = proc_info.name.clone();
            let mut process = os
                .into_process_by_info(proc_info)
                .context("unable to open selected process")?;
            let modules = process
                .module_list()
                .context("unable to read selected process module list")?
                .into_iter()
                .take(request.limit)
                .map(|m| ModuleRecord {
                    base: m.base.to_umem(),
                    name: m.name.to_string(),
                    path: m.path.to_string(),
                })
                .collect();

            Some(ProcessTriage {
                pid,
                name: resolved_name.to_string(),
                modules,
            })
        } else {
            None
        };

        Ok(TriageReport {
            processes,
            selected_process,
        })
    }

    pub fn envars(&self, request: &EnvarsRequest) -> Result<EnvarsReport> {
        let connector = self.open_connector()?;
        let mut os = Win32Kernel::builder(connector)
            .build_default_caches()
            .build()
            .context("failed to initialize win32 OS layer")?;

        let proc_info = os
            .process_info_by_pid(request.pid)
            .with_context(|| format!("process not found in list: pid={}", request.pid))?;
        let process_name = proc_info.name.to_string();
        let mut process = os
            .into_process_by_info(proc_info)
            .context("unable to open selected process")?;

        let variables = if let Some(name) = request.name.as_deref() {
            let variable = process
                .envar_by_name(name)
                .with_context(|| format!("environment variable not found: {name}"))?;
            vec![EnvarRecord {
                name: variable.name.to_string(),
                value: variable.value.to_string(),
                address: variable.address.to_umem(),
                arch: variable.arch.to_string(),
            }]
        } else {
            process
                .envar_list()
                .context("unable to retrieve environment variables list")?
                .into_iter()
                .map(|variable| EnvarRecord {
                    name: variable.name.to_string(),
                    value: variable.value.to_string(),
                    address: variable.address.to_umem(),
                    arch: variable.arch.to_string(),
                })
                .collect()
        };

        Ok(EnvarsReport {
            pid: request.pid,
            process_name,
            variables,
        })
    }

    pub fn memdump(&self, request: &MemdumpRequest) -> Result<MemdumpReport> {
        self.memdump_with_callbacks(request, &MemdumpCallbacks::default())
    }

    pub fn memdump_with_callbacks(
        &self,
        request: &MemdumpRequest,
        callbacks: &MemdumpCallbacks,
    ) -> Result<MemdumpReport> {
        const DUMP_START: u64 = 0;

        if request.chunk_size == 0 {
            anyhow::bail!("chunk_size must be > 0");
        }

        let mut connector = self.open_connector()?;
        let end = crate::connector::resolve_physical_end(connector.clone(), request.end)?;
        if end <= DUMP_START {
            anyhow::bail!("invalid range: end must be greater than start");
        }
        let file = File::create(&request.output).with_context(|| {
            format!("failed to create output file: {}", request.output.display())
        })?;
        let mut writer = BufWriter::new(file);
        let mut cursor = DUMP_START;
        let total = end - DUMP_START;
        let mut dumped = 0u64;
        let mut chunk_index = 0u64;
        let chunk_count = total.div_ceil(request.chunk_size as u64);

        while cursor < end {
            let remaining = (end - cursor) as usize;
            let read_len = remaining.min(request.chunk_size);
            let mut buf = vec![0u8; read_len];
            connector
                .phys_view()
                .read_raw_into(Address::from(cursor), &mut buf)
                .with_context(|| {
                    format!("failed reading physical chunk at {cursor:#x}, size={read_len:#x}")
                })?;
            writer
                .write_all(&buf)
                .context("failed writing dump chunk to file")?;

            cursor += read_len as u64;
            dumped += read_len as u64;
            chunk_index += 1;
            log::info!(
                "dumped {:#x}/{:#x} bytes ({:.2}%)",
                dumped,
                total,
                dumped as f64 * 100.0 / total as f64
            );

            if should_emit_progress_update(chunk_index, chunk_count) {
                emit_progress(
                    &callbacks.on_progress,
                    dumped,
                    total,
                    format!("dumped {dumped:#x}/{total:#x} bytes"),
                );
            }
        }

        writer.flush().context("failed flushing output file")?;

        Ok(MemdumpReport {
            dump_start: DUMP_START,
            dump_end: end,
            bytes_dumped: dumped,
            output: request.output.clone(),
        })
    }

    pub fn scan_bitlocker(&self, request: &BitlockerScanRequest) -> Result<BitlockerScanReport> {
        scan_bitlocker(&self.connector_options, request)
    }
}

fn should_emit_progress_update(current: u64, total: u64) -> bool {
    current == 1 || current == total || current % 32 == 0
}

fn emit_progress(callback: &Option<ProgressCallback>, current: u64, total: u64, message: String) {
    if let Some(callback) = callback {
        callback(MemoryProgressUpdate {
            current,
            total,
            message,
        });
    }
}
