use std::sync::{Mutex, OnceLock};

use anyhow::{Result, anyhow};
use memflow::mem::phys_mem::{PhysicalMemory, PhysicalMemoryMetadata};
use memflow::prelude::v1::*;
use memflow_win32::prelude::v1::*;

use crate::cli::ConnectorKind;

#[derive(Debug, Clone)]
pub struct ConnectorOptions {
    pub connector: String,
    pub kind: ConnectorKind,
}

#[derive(Clone)]
pub enum Connector {
    Pcileech(memflow_pcileech::PciLeech),
    Rawmem(memflow_rawmem::MemRawRo<'static>),
}

#[derive(Clone)]
struct CachedPcileechConnector {
    descriptor: String,
    connector: memflow_pcileech::PciLeech,
}

fn pcileech_cache() -> &'static Mutex<Option<CachedPcileechConnector>> {
    static CACHE: OnceLock<Mutex<Option<CachedPcileechConnector>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(None))
}

impl ConnectorOptions {
    pub fn open(&self) -> Result<Connector> {
        let connector_args = self
            .connector
            .parse()
            .map_err(|e| anyhow!("failed to parse connector args: {e}"))?;

        match self.kind {
            ConnectorKind::Pcileech => {
                let mut cache = pcileech_cache()
                    .lock()
                    .map_err(|_| anyhow!("failed to acquire pcileech connector cache lock"))?;

                if let Some(cached) = cache.as_ref() {
                    if cached.descriptor != self.connector {
                        return Err(anyhow!(
                            "pcileech connector already initialized for '{}' and cannot be changed without restarting the process",
                            cached.descriptor
                        ));
                    }

                    return Ok(Connector::Pcileech(cached.connector.clone()));
                }

                let conn = memflow_pcileech::create_connector(&connector_args)
                    .map_err(|e| anyhow!("failed to create memflow-pcileech connector: {e}"))?;
                *cache = Some(CachedPcileechConnector {
                    descriptor: self.connector.clone(),
                    connector: conn.clone(),
                });
                Ok(Connector::Pcileech(conn))
            }
            ConnectorKind::Rawmem => {
                let conn = memflow_rawmem::create_connector(&connector_args)
                    .map_err(|e| anyhow!("failed to create memflow-rawmem connector: {e}"))?;
                // Safety: MemRawRo created via create_connector owns its resources.
                let conn_static = unsafe {
                    std::mem::transmute::<
                        memflow_rawmem::MemRawRo<'_>,
                        memflow_rawmem::MemRawRo<'static>,
                    >(conn)
                };
                Ok(Connector::Rawmem(conn_static))
            }
        }
    }

    pub fn metadata(&self) -> Result<PhysicalMemoryMetadata> {
        Ok(self.open()?.metadata())
    }
}

pub fn resolve_physical_end(connector: Connector, requested_end: Option<u64>) -> Result<u64> {
    if let Some(end) = requested_end {
        return Ok(end);
    }

    let metadata_last = connector.metadata().max_address.to_umem();
    if matches!(connector, Connector::Rawmem(_)) || metadata_last > 0x100000000 {
        return Ok(metadata_last.saturating_add(1));
    }

    let kernel_connector = connector.clone();
    if let Ok(mut kernel) = Win32Kernel::builder(kernel_connector).build() {
        let kernel_last = kernel.phys_view().metadata().max_address.to_umem();
        if kernel_last > metadata_last {
            let kernel_end = kernel_last.saturating_add(1);
            log::info!("Win32 probe discovered larger physical address space: {kernel_end:#x}");
            return Ok(kernel_end);
        }
    }

    Ok(metadata_last.saturating_add(1))
}

impl PhysicalMemory for Connector {
    fn phys_read_raw_iter(
        &mut self,
        data: memflow::mem::mem_data::PhysicalReadMemOps,
    ) -> memflow::error::Result<()> {
        match self {
            Connector::Pcileech(c) => c.phys_read_raw_iter(data),
            Connector::Rawmem(c) => c.phys_read_raw_iter(data),
        }
    }

    fn phys_write_raw_iter(
        &mut self,
        data: memflow::mem::mem_data::PhysicalWriteMemOps,
    ) -> memflow::error::Result<()> {
        match self {
            Connector::Pcileech(c) => c.phys_write_raw_iter(data),
            Connector::Rawmem(c) => c.phys_write_raw_iter(data),
        }
    }

    fn metadata(&self) -> memflow::mem::phys_mem::PhysicalMemoryMetadata {
        match self {
            Connector::Pcileech(c) => c.metadata(),
            Connector::Rawmem(c) => c.metadata(),
        }
    }

    fn set_mem_map(&mut self, mem_map: &[memflow::mem::mem_map::PhysicalMemoryMapping]) {
        match self {
            Connector::Pcileech(c) => c.set_mem_map(mem_map),
            Connector::Rawmem(c) => c.set_mem_map(mem_map),
        }
    }
}
