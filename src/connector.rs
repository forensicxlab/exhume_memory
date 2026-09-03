use std::path::PathBuf;

use anyhow::{Context, Result, anyhow};
use memflow::mem::phys_mem::{PhysicalMemory, PhysicalMemoryMetadata};
use memflow::prelude::v1::*;
use memflow_win32::prelude::v1::*;

use crate::cli::{ConnectorKind, OsKind};
use crate::source::{
    ConnectorSourceDescriptor, MemorySourceIdentity, MemorySourceInspection, PhysicalMemoryRange,
    classify_connector_descriptor, inspect_descriptor_image, validate_physical_ranges,
};

#[derive(Debug, Clone)]
pub struct ConnectorOptions {
    pub connector: String,
    pub kind: ConnectorKind,
    pub os_kind: OsKind,
    pub linux_profile: Option<PathBuf>,
}

#[derive(Clone)]
pub enum Connector {
    Pcileech(memflow_pcileech::PciLeech),
    #[cfg(target_os = "linux")]
    Kvm(memflow_kvm::KVMConnector<'static>),
    Rawmem(memflow_rawmem::MemRawRo<'static>),
}

impl ConnectorOptions {
    /// Parses the configured source without opening a connector.
    pub fn source_descriptor(&self) -> Result<crate::source::MemoryConnectorDescriptor> {
        classify_connector_descriptor(self.kind, &self.connector)
    }

    /// Validates the acquisition source without constructing an OS layer.
    ///
    /// File images are inspected directly. Live sources are opened only far
    /// enough to retrieve their connector-level physical map.
    pub fn inspect_source(&self) -> Result<MemorySourceInspection> {
        let descriptor = self.source_descriptor()?;
        match &descriptor.source {
            ConnectorSourceDescriptor::MemoryImage { .. } => {
                let mut inspection = inspect_descriptor_image(&descriptor)?;
                if self.kind == ConnectorKind::Pcileech {
                    let connector = self
                        .open_unvalidated()
                        .context("failed to open validated pcileech image source")?;
                    inspection.readable_ranges = connector.readable_ranges()?;
                }
                Ok(inspection)
            }
            ConnectorSourceDescriptor::LiveDma => {
                let connector = self.open_unvalidated()?;
                let readable_ranges = connector.readable_ranges()?;
                Ok(MemorySourceInspection {
                    identity: MemorySourceIdentity::LiveDma,
                    connector_kind: self.kind,
                    descriptor: self.connector.clone(),
                    file_size: None,
                    readable_ranges,
                })
            }
        }
    }

    pub fn open(&self) -> Result<Connector> {
        let descriptor = self.source_descriptor()?;
        if matches!(
            &descriptor.source,
            ConnectorSourceDescriptor::MemoryImage { .. }
        ) {
            // Validate connector/format compatibility before a backend can
            // silently identity-map a sparse image.
            inspect_descriptor_image(&descriptor)?;
        }
        self.open_unvalidated()
    }

    fn open_unvalidated(&self) -> Result<Connector> {
        let connector_args = self
            .connector
            .parse()
            .map_err(|e| anyhow!("failed to parse connector args: {e}"))?;

        match self.kind {
            ConnectorKind::Pcileech => {
                let conn = memflow_pcileech::create_connector(&connector_args)
                    .map_err(|e| anyhow!("failed to create memflow-pcileech connector: {e}"))?;
                Ok(Connector::Pcileech(conn))
            }
            ConnectorKind::Kvm => {
                #[cfg(target_os = "linux")]
                {
                    let conn = memflow_kvm::create_connector(&connector_args)
                        .map_err(|e| anyhow!("failed to create memflow-kvm connector: {e}"))?;
                    // Safety: KVMConnector owns the mapped VM memory via its map data. The connector
                    // is stored in the enum and dropped with it; no borrowed input data escapes.
                    let conn_static = unsafe {
                        std::mem::transmute::<
                            memflow_kvm::KVMConnector<'_>,
                            memflow_kvm::KVMConnector<'static>,
                        >(conn)
                    };
                    Ok(Connector::Kvm(conn_static))
                }

                #[cfg(not(target_os = "linux"))]
                {
                    Err(anyhow!("memflow-kvm is only supported on Linux hosts"))
                }
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

impl Connector {
    /// Returns explicit readable physical ranges as half-open intervals.
    pub fn readable_ranges(&self) -> Result<Vec<PhysicalMemoryRange>> {
        let ranges = match self {
            Connector::Pcileech(connector) => connector
                .physical_memory_ranges()
                .map_err(|err| anyhow!("failed to query pcileech physical ranges: {err}"))?
                .into_iter()
                .map(|range| PhysicalMemoryRange {
                    start: range.start,
                    end: range.end,
                    source_offset: Some(range.source_offset),
                })
                .collect::<Vec<_>>(),
            Connector::Rawmem(connector) => contiguous_metadata_range(connector.metadata())?,
            #[cfg(target_os = "linux")]
            Connector::Kvm(_) => anyhow::bail!(
                "memflow-kvm does not expose its individual readable memory slots through the connector API"
            ),
        };

        validate_physical_ranges(&ranges).context("connector returned an invalid physical map")?;
        Ok(ranges)
    }
}

fn contiguous_metadata_range(metadata: PhysicalMemoryMetadata) -> Result<Vec<PhysicalMemoryRange>> {
    let end = metadata
        .max_address
        .to_umem()
        .checked_add(1)
        .ok_or_else(|| anyhow!("connector maximum physical address overflows"))?;
    let size = u64::try_from(metadata.real_size)
        .map_err(|_| anyhow!("connector real size does not fit u64"))?;
    let start = end.checked_sub(size).ok_or_else(|| {
        anyhow!("connector real size exceeds its reported physical address envelope")
    })?;
    Ok(vec![PhysicalMemoryRange::from_len(start, size, None)?])
}

pub fn resolve_physical_end(connector: Connector, requested_end: Option<u64>) -> Result<u64> {
    if let Some(end) = requested_end {
        return Ok(end);
    }

    let metadata_last = connector.metadata().max_address.to_umem();
    if is_direct_mapped_connector(&connector) || metadata_last > 0x100000000 {
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
            #[cfg(target_os = "linux")]
            Connector::Kvm(c) => c.phys_read_raw_iter(data),
            Connector::Rawmem(c) => c.phys_read_raw_iter(data),
        }
    }

    fn phys_write_raw_iter(
        &mut self,
        data: memflow::mem::mem_data::PhysicalWriteMemOps,
    ) -> memflow::error::Result<()> {
        match self {
            Connector::Pcileech(c) => c.phys_write_raw_iter(data),
            #[cfg(target_os = "linux")]
            Connector::Kvm(c) => c.phys_write_raw_iter(data),
            Connector::Rawmem(c) => c.phys_write_raw_iter(data),
        }
    }

    fn metadata(&self) -> memflow::mem::phys_mem::PhysicalMemoryMetadata {
        match self {
            Connector::Pcileech(c) => c.metadata(),
            #[cfg(target_os = "linux")]
            Connector::Kvm(c) => c.metadata(),
            Connector::Rawmem(c) => c.metadata(),
        }
    }

    fn set_mem_map(&mut self, mem_map: &[memflow::mem::mem_map::PhysicalMemoryMapping]) {
        match self {
            Connector::Pcileech(c) => c.set_mem_map(mem_map),
            #[cfg(target_os = "linux")]
            Connector::Kvm(c) => c.set_mem_map(mem_map),
            Connector::Rawmem(c) => c.set_mem_map(mem_map),
        }
    }
}

fn is_direct_mapped_connector(connector: &Connector) -> bool {
    if matches!(connector, Connector::Rawmem(_)) {
        return true;
    }

    #[cfg(target_os = "linux")]
    {
        if matches!(connector, Connector::Kvm(_)) {
            return true;
        }
    }

    false
}
