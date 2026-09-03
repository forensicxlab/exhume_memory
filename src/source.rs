use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use memflow::plugins::ConnectorArgs;
use serde::Serialize;

use crate::cli::ConnectorKind;

const ELF_MAGIC: &[u8; 4] = b"\x7fELF";
const WINDOWS_DUMP32_MAGIC: &[u8; 8] = b"PAGEDUMP";
const WINDOWS_DUMP64_MAGIC: &[u8; 8] = b"PAGEDU64";
const ELF_PT_LOAD: u32 = 1;
const ELF_ET_CORE: u16 = 4;
const ELF_CURRENT_VERSION: u32 = 1;
const PAGE_SIZE: u64 = 0x1000;
const MAX_ELF_PROGRAM_HEADER_TABLE_SIZE: u64 = 16 * 1024 * 1024;
const MAX_WINDOWS_PHYSICAL_RUNS: usize = 0x80;

/// The acquisition source represented by a connector descriptor.
///
/// A file-backed pcileech descriptor with no recoverable path is retained as
/// an image descriptor so callers get a precise missing-path error instead of
/// accidentally treating it as live DMA.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectorSourceDescriptor {
    LiveDma,
    MemoryImage {
        path: Option<PathBuf>,
        physical_base: u64,
    },
}

/// Parsed connector information, without opening a connector or probing an OS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryConnectorDescriptor {
    pub connector_kind: ConnectorKind,
    pub descriptor: String,
    pub source: ConnectorSourceDescriptor,
}

/// A validated memory image format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryImageFormat {
    ElfCore,
    FlatRaw,
    WindowsCrashDump,
}

/// Stable source identity returned by source inspection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum MemorySourceIdentity {
    LiveDma,
    MemoryImage {
        path: PathBuf,
        format: MemoryImageFormat,
    },
}

/// A readable half-open physical range (`start..end`).
///
/// `source_offset`, when present, is the corresponding offset in the backing
/// image. It is intentionally distinct from `start`: sparse formats such as ELF
/// core and Windows crash dumps do not use identity file mappings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct PhysicalMemoryRange {
    pub start: u64,
    pub end: u64,
    pub source_offset: Option<u64>,
}

impl PhysicalMemoryRange {
    pub fn from_len(start: u64, len: u64, source_offset: Option<u64>) -> Result<Self> {
        if len == 0 {
            bail!("physical memory range at {start:#x} is empty");
        }
        let end = start.checked_add(len).ok_or_else(|| {
            anyhow!("physical memory range overflows: start={start:#x}, length={len:#x}")
        })?;
        if let Some(offset) = source_offset {
            offset.checked_add(len).ok_or_else(|| {
                anyhow!("source range overflows: offset={offset:#x}, length={len:#x}")
            })?;
        }

        Ok(Self {
            start,
            end,
            source_offset,
        })
    }

    pub const fn len(self) -> u64 {
        self.end - self.start
    }

    pub const fn is_empty(self) -> bool {
        self.start == self.end
    }

    /// Converts this source range into Scanflow's half-open range type.
    pub fn to_scan_range(
        self,
    ) -> std::result::Result<scanflow::range_scanner::ScanRange, scanflow::range_scanner::ScanError>
    {
        scanflow::range_scanner::ScanRange::new(self.start.into(), self.end.into())
    }
}

/// Source metadata that can be obtained without constructing a Windows or
/// Linux OS layer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MemorySourceInspection {
    pub identity: MemorySourceIdentity,
    pub connector_kind: ConnectorKind,
    pub descriptor: String,
    pub file_size: Option<u64>,
    pub readable_ranges: Vec<PhysicalMemoryRange>,
}

impl MemorySourceInspection {
    /// Returns the exact readable ranges expected by Scanflow. Sparse holes are
    /// kept separate and therefore cannot be scanned as synthetic memory.
    pub fn scan_ranges(
        &self,
    ) -> std::result::Result<
        Vec<scanflow::range_scanner::ScanRange>,
        scanflow::range_scanner::ScanError,
    > {
        self.readable_ranges
            .iter()
            .copied()
            .map(PhysicalMemoryRange::to_scan_range)
            .collect()
    }
}

#[derive(Debug)]
struct MemoryImageInspection {
    format: MemoryImageFormat,
    file_size: u64,
    readable_ranges: Vec<PhysicalMemoryRange>,
}

#[derive(Debug, Clone, Copy)]
enum ElfClass {
    Elf32,
    Elf64,
}

/// Classifies a connector descriptor without opening its target.
pub fn classify_connector_descriptor(
    connector_kind: ConnectorKind,
    descriptor: &str,
) -> Result<MemoryConnectorDescriptor> {
    let args: ConnectorArgs = descriptor
        .parse()
        .map_err(|err| anyhow!("failed to parse connector args: {err}"))?;

    let source = match connector_kind {
        ConnectorKind::Rawmem => {
            let path = args.target.as_deref().filter(|value| !value.is_empty());
            let path = path
                .map(PathBuf::from)
                .ok_or_else(|| anyhow!("rawmem connector requires a memory image path"))?;
            let physical_base = args
                .extra_args
                .get("base")
                .map(|base| parse_u64_value(base, "rawmem base"))
                .transpose()?
                .unwrap_or(0);
            ConnectorSourceDescriptor::MemoryImage {
                path: Some(path),
                physical_base,
            }
        }
        ConnectorKind::Pcileech => {
            let device = args
                .extra_args
                .get("device")
                .or_else(|| args.extra_args.get_default())
                .ok_or_else(|| anyhow!("pcileech connector requires a device descriptor"))?;

            match pcileech_file_path(device) {
                PcileechDevice::LiveDma => ConnectorSourceDescriptor::LiveDma,
                PcileechDevice::MemoryImage(path) => ConnectorSourceDescriptor::MemoryImage {
                    path,
                    physical_base: 0,
                },
            }
        }
        ConnectorKind::Kvm => ConnectorSourceDescriptor::LiveDma,
    };

    Ok(MemoryConnectorDescriptor {
        connector_kind,
        descriptor: descriptor.to_owned(),
        source,
    })
}

/// Detects an image type from its leading bytes. Unknown magic is a flat image;
/// format-specific validation is performed by [`inspect_memory_image`].
pub fn detect_memory_image_format(prefix: &[u8]) -> MemoryImageFormat {
    if prefix.starts_with(ELF_MAGIC) {
        MemoryImageFormat::ElfCore
    } else if prefix.starts_with(WINDOWS_DUMP32_MAGIC) || prefix.starts_with(WINDOWS_DUMP64_MAGIC) {
        MemoryImageFormat::WindowsCrashDump
    } else {
        MemoryImageFormat::FlatRaw
    }
}

/// Inspects and validates an image at physical base zero.
pub fn inspect_memory_image(path: impl AsRef<Path>) -> Result<MemorySourceInspection> {
    let path = path.as_ref();
    let image = inspect_memory_image_at_base(path, 0)?;
    Ok(MemorySourceInspection {
        identity: MemorySourceIdentity::MemoryImage {
            path: path.to_path_buf(),
            format: image.format,
        },
        connector_kind: ConnectorKind::Pcileech,
        descriptor: path.display().to_string(),
        file_size: Some(image.file_size),
        readable_ranges: image.readable_ranges,
    })
}

pub(crate) fn inspect_descriptor_image(
    descriptor: &MemoryConnectorDescriptor,
) -> Result<MemorySourceInspection> {
    let ConnectorSourceDescriptor::MemoryImage {
        path,
        physical_base,
    } = &descriptor.source
    else {
        bail!("connector descriptor does not identify a memory image");
    };

    let path = path.as_ref().ok_or_else(|| {
        anyhow!(
            "pcileech device=file identifies a memory image but does not provide an inspectable path; use :device=/absolute/path or :device=\"file:///absolute/path\""
        )
    })?;
    let image = inspect_memory_image_at_base(path, *physical_base)?;

    if descriptor.connector_kind == ConnectorKind::Rawmem
        && image.format != MemoryImageFormat::FlatRaw
    {
        bail!(
            "rawmem cannot open {:?} images because it maps file offsets directly as physical addresses; use pcileech with a file device so the image's physical ranges are honored",
            image.format
        );
    }

    Ok(MemorySourceInspection {
        identity: MemorySourceIdentity::MemoryImage {
            path: path.clone(),
            format: image.format,
        },
        connector_kind: descriptor.connector_kind,
        descriptor: descriptor.descriptor.clone(),
        file_size: Some(image.file_size),
        readable_ranges: image.readable_ranges,
    })
}

fn inspect_memory_image_at_base(path: &Path, flat_base: u64) -> Result<MemoryImageInspection> {
    let mut file = File::open(path)
        .with_context(|| format!("failed to open memory image: {}", path.display()))?;
    let file_size = file
        .metadata()
        .with_context(|| format!("failed to stat memory image: {}", path.display()))?
        .len();
    if file_size == 0 {
        bail!("memory image is empty: {}", path.display());
    }

    let prefix_len = usize::try_from(file_size.min(64)).expect("prefix length is bounded");
    let mut prefix = vec![0u8; prefix_len];
    file.read_exact(&mut prefix)
        .with_context(|| format!("failed reading memory image header: {}", path.display()))?;
    let format = detect_memory_image_format(&prefix);

    let mut readable_ranges = match format {
        MemoryImageFormat::ElfCore => parse_elf_ranges(&mut file, file_size, &prefix)?,
        MemoryImageFormat::WindowsCrashDump => {
            parse_windows_crash_dump_ranges(&mut file, file_size, &prefix)?
        }
        MemoryImageFormat::FlatRaw => vec![PhysicalMemoryRange::from_len(
            flat_base,
            file_size,
            Some(0),
        )?],
    };

    readable_ranges.sort_unstable_by_key(|range| range.start);
    validate_physical_ranges(&readable_ranges)?;

    Ok(MemoryImageInspection {
        format,
        file_size,
        readable_ranges,
    })
}

/// Validates that ranges are non-empty, non-overflowing, and physically
/// non-overlapping. Input order is not significant.
pub fn validate_physical_ranges(ranges: &[PhysicalMemoryRange]) -> Result<()> {
    if ranges.is_empty() {
        bail!("memory source has no readable physical ranges");
    }

    let mut sorted = ranges.to_vec();
    sorted.sort_unstable_by_key(|range| range.start);
    for range in &sorted {
        if range.end <= range.start {
            bail!(
                "invalid physical memory range: {:#x}..{:#x}",
                range.start,
                range.end
            );
        }
        let length = range.end - range.start;
        if let Some(offset) = range.source_offset {
            offset.checked_add(length).ok_or_else(|| {
                anyhow!("source range overflows: offset={offset:#x}, length={length:#x}")
            })?;
        }
    }

    for adjacent in sorted.windows(2) {
        if adjacent[0].end > adjacent[1].start {
            bail!(
                "overlapping physical ranges: {:#x}..{:#x} and {:#x}..{:#x}",
                adjacent[0].start,
                adjacent[0].end,
                adjacent[1].start,
                adjacent[1].end
            );
        }
    }

    Ok(())
}

fn validate_source_ranges_do_not_overlap(ranges: &[PhysicalMemoryRange]) -> Result<()> {
    let mut backed = ranges
        .iter()
        .filter_map(|range| {
            range
                .source_offset
                .map(|offset| (offset, offset + range.len()))
        })
        .collect::<Vec<_>>();
    backed.sort_unstable_by_key(|range| range.0);

    for adjacent in backed.windows(2) {
        if adjacent[0].1 > adjacent[1].0 {
            bail!(
                "overlapping image ranges: {:#x}..{:#x} and {:#x}..{:#x}",
                adjacent[0].0,
                adjacent[0].1,
                adjacent[1].0,
                adjacent[1].1
            );
        }
    }
    Ok(())
}

fn parse_elf_ranges(
    file: &mut File,
    file_size: u64,
    prefix: &[u8],
) -> Result<Vec<PhysicalMemoryRange>> {
    if prefix.len() < 16 {
        bail!("truncated ELF identification header");
    }
    if prefix[5] != 1 {
        bail!("only little-endian ELF core images are supported");
    }
    if prefix[6] != 1 {
        bail!("unsupported ELF identification version: {}", prefix[6]);
    }

    let class = match prefix[4] {
        1 => ElfClass::Elf32,
        2 => ElfClass::Elf64,
        other => bail!("unsupported ELF class: {other}"),
    };
    let header_size = match class {
        ElfClass::Elf32 => 52usize,
        ElfClass::Elf64 => 64usize,
    };
    let mut header = vec![0u8; header_size];
    read_exact_at(file, 0, &mut header, "ELF header")?;

    let elf_type = read_u16(&header, 16, "ELF type")?;
    if elf_type != ELF_ET_CORE {
        bail!("ELF image is not a core dump: e_type={elf_type:#x}");
    }
    let version = read_u32(&header, 20, "ELF version")?;
    if version != ELF_CURRENT_VERSION {
        bail!("unsupported ELF version: {version}");
    }

    let (program_offset, entry_size, entry_count, required_entry_size) = match class {
        ElfClass::Elf32 => (
            u64::from(read_u32(&header, 28, "ELF program-header offset")?),
            usize::from(read_u16(&header, 42, "ELF program-header entry size")?),
            usize::from(read_u16(&header, 44, "ELF program-header count")?),
            32usize,
        ),
        ElfClass::Elf64 => (
            read_u64(&header, 32, "ELF program-header offset")?,
            usize::from(read_u16(&header, 54, "ELF program-header entry size")?),
            usize::from(read_u16(&header, 56, "ELF program-header count")?),
            56usize,
        ),
    };

    if entry_count == 0 {
        bail!("ELF core image has no program headers");
    }
    if entry_count == usize::from(u16::MAX) {
        bail!("extended ELF program-header counts are not supported");
    }
    if entry_size != required_entry_size {
        bail!(
            "unsupported ELF program-header entry size: expected {required_entry_size}, got {entry_size}"
        );
    }
    if program_offset < u64::try_from(header_size).expect("ELF header size fits u64") {
        bail!("ELF program-header table overlaps the ELF header");
    }

    let table_size = u64::try_from(entry_size)
        .expect("ELF entry size fits u64")
        .checked_mul(u64::try_from(entry_count).expect("ELF entry count fits u64"))
        .ok_or_else(|| anyhow!("ELF program-header table size overflows"))?;
    if table_size > MAX_ELF_PROGRAM_HEADER_TABLE_SIZE {
        bail!("ELF program-header table is unreasonably large: {table_size:#x} bytes");
    }
    let table_end = program_offset
        .checked_add(table_size)
        .ok_or_else(|| anyhow!("ELF program-header table offset overflows"))?;
    if table_end > 0x2000 {
        bail!(
            "ELF program-header table ends at {table_end:#x}; pcileech's file backend requires the complete table within the first 0x2000 bytes"
        );
    }
    if table_end > file_size {
        bail!(
            "ELF program-header table exceeds file size: end={table_end:#x}, file={file_size:#x}"
        );
    }

    let mut table = vec![0u8; usize::try_from(table_size).expect("ELF table is size-capped")];
    read_exact_at(file, program_offset, &mut table, "ELF program-header table")?;

    let mut ranges = Vec::new();
    for index in 0..entry_count {
        let start = index * entry_size;
        let entry = &table[start..start + entry_size];
        if read_u32(entry, 0, "ELF program-header type")? != ELF_PT_LOAD {
            continue;
        }

        let (source_offset, physical_start, file_length, memory_length) = match class {
            ElfClass::Elf32 => (
                u64::from(read_u32(entry, 4, "ELF p_offset")?),
                u64::from(read_u32(entry, 12, "ELF p_paddr")?),
                u64::from(read_u32(entry, 16, "ELF p_filesz")?),
                u64::from(read_u32(entry, 20, "ELF p_memsz")?),
            ),
            ElfClass::Elf64 => (
                read_u64(entry, 8, "ELF p_offset")?,
                read_u64(entry, 24, "ELF p_paddr")?,
                read_u64(entry, 32, "ELF p_filesz")?,
                read_u64(entry, 40, "ELF p_memsz")?,
            ),
        };

        if file_length == 0 {
            continue;
        }
        if source_offset == 0 {
            bail!("ELF PT_LOAD[{index}] maps the ELF header as memory");
        }
        if file_length != memory_length {
            bail!(
                "ELF PT_LOAD[{index}] has p_filesz={file_length:#x} but p_memsz={memory_length:#x}; pcileech file images require fully captured segments"
            );
        }
        if physical_start % PAGE_SIZE != 0 || file_length % PAGE_SIZE != 0 {
            bail!(
                "ELF PT_LOAD[{index}] is not page aligned: p_paddr={physical_start:#x}, p_filesz={file_length:#x}"
            );
        }

        let source_end = source_offset.checked_add(file_length).ok_or_else(|| {
            anyhow!(
                "ELF PT_LOAD[{index}] file range overflows: p_offset={source_offset:#x}, p_filesz={file_length:#x}"
            )
        })?;
        if source_end > file_size {
            bail!(
                "ELF PT_LOAD[{index}] exceeds file size: file range={source_offset:#x}..{source_end:#x}, file={file_size:#x}"
            );
        }

        let range = PhysicalMemoryRange::from_len(physical_start, file_length, Some(source_offset))
            .with_context(|| format!("invalid ELF PT_LOAD[{index}] physical range"))?;
        ensure_next_range_is_ordered(&ranges, range, &format!("ELF PT_LOAD[{index}]"))?;
        ranges.push(range);
    }

    validate_physical_ranges(&ranges).context("invalid ELF physical memory map")?;
    validate_source_ranges_do_not_overlap(&ranges).context("invalid ELF file map")?;
    Ok(ranges)
}

fn parse_windows_crash_dump_ranges(
    file: &mut File,
    file_size: u64,
    prefix: &[u8],
) -> Result<Vec<PhysicalMemoryRange>> {
    let is_64 = prefix.starts_with(WINDOWS_DUMP64_MAGIC);
    let header_size = if is_64 { 0x2000usize } else { 0x1000usize };
    if file_size < u64::try_from(header_size).expect("dump header size fits u64") {
        bail!("truncated Windows crash dump header");
    }

    let mut header = vec![0u8; header_size];
    read_exact_at(file, 0, &mut header, "Windows crash dump header")?;

    let (machine_offset, expected_machines, dump_type_offset, descriptor_offset, run_size) =
        if is_64 {
            (
                0x30usize,
                &[0x8664u32, 0xaa64u32][..],
                0xf98usize,
                0x88usize,
                16usize,
            )
        } else {
            (0x20usize, &[0x014cu32][..], 0xf88usize, 0x64usize, 8usize)
        };
    let machine = read_u32(&header, machine_offset, "crash dump machine")?;
    if !expected_machines.contains(&machine) {
        bail!("unsupported Windows crash dump machine: {machine:#x}");
    }
    let dump_type = read_u32(&header, dump_type_offset, "crash dump type")?;
    if dump_type != 1 {
        bail!(
            "Windows crash dump type {dump_type} is recognized but source inspection currently supports full dumps only"
        );
    }

    let run_count = usize::try_from(read_u32(&header, descriptor_offset, "physical run count")?)
        .expect("u32 fits usize on supported hosts");
    if run_count == 0 || run_count > MAX_WINDOWS_PHYSICAL_RUNS {
        bail!("invalid Windows crash dump physical run count: {run_count}");
    }
    let runs_offset = descriptor_offset + if is_64 { 16 } else { 8 };
    let runs_end = runs_offset
        .checked_add(
            run_count
                .checked_mul(run_size)
                .ok_or_else(|| anyhow!("Windows crash dump physical run table size overflows"))?,
        )
        .ok_or_else(|| anyhow!("Windows crash dump physical run table offset overflows"))?;
    if runs_end > header.len() {
        bail!("Windows crash dump physical run table exceeds its header");
    }

    let mut source_offset = u64::try_from(header_size).expect("dump header size fits u64");
    let mut ranges = Vec::with_capacity(run_count);
    let mut page_count_sum = 0u64;
    for index in 0..run_count {
        let offset = runs_offset + index * run_size;
        let (base_page, page_count) = if is_64 {
            (
                read_u64(&header, offset, "physical run base page")?,
                read_u64(&header, offset + 8, "physical run page count")?,
            )
        } else {
            (
                u64::from(read_u32(&header, offset, "physical run base page")?),
                u64::from(read_u32(&header, offset + 4, "physical run page count")?),
            )
        };
        if page_count == 0 {
            bail!("Windows crash dump physical run {index} is empty");
        }

        let start = base_page
            .checked_mul(PAGE_SIZE)
            .ok_or_else(|| anyhow!("Windows crash dump physical run {index} base overflows"))?;
        let length = page_count
            .checked_mul(PAGE_SIZE)
            .ok_or_else(|| anyhow!("Windows crash dump physical run {index} length overflows"))?;
        let source_end = source_offset.checked_add(length).ok_or_else(|| {
            anyhow!("Windows crash dump physical run {index} file range overflows")
        })?;
        if source_end > file_size {
            bail!(
                "Windows crash dump physical run {index} exceeds file size: end={source_end:#x}, file={file_size:#x}"
            );
        }

        let range = PhysicalMemoryRange::from_len(start, length, Some(source_offset))?;
        ensure_next_range_is_ordered(
            &ranges,
            range,
            &format!("Windows crash dump physical run {index}"),
        )?;
        ranges.push(range);
        source_offset = source_end;
        page_count_sum = page_count_sum
            .checked_add(page_count)
            .ok_or_else(|| anyhow!("Windows crash dump page count overflows"))?;
    }

    let declared_pages = u64::from(read_u32(
        &header,
        descriptor_offset + if is_64 { 8 } else { 4 },
        "declared physical page count",
    )?);
    if declared_pages != 0 && declared_pages != page_count_sum {
        bail!(
            "Windows crash dump page count mismatch: header={declared_pages}, runs={page_count_sum}"
        );
    }

    validate_physical_ranges(&ranges).context("invalid Windows crash dump physical map")?;
    Ok(ranges)
}

fn ensure_next_range_is_ordered(
    existing: &[PhysicalMemoryRange],
    next: PhysicalMemoryRange,
    label: &str,
) -> Result<()> {
    let Some(previous) = existing.last() else {
        return Ok(());
    };
    if next.start < previous.start {
        bail!(
            "{label} is not in ascending physical-address order: previous={:#x}..{:#x}, next={:#x}..{:#x}",
            previous.start,
            previous.end,
            next.start,
            next.end
        );
    }
    if next.start < previous.end {
        bail!(
            "overlapping physical ranges: {:#x}..{:#x} and {:#x}..{:#x}",
            previous.start,
            previous.end,
            next.start,
            next.end
        );
    }
    Ok(())
}

fn read_exact_at(file: &mut File, offset: u64, buffer: &mut [u8], what: &str) -> Result<()> {
    file.seek(SeekFrom::Start(offset))
        .with_context(|| format!("failed seeking to {what} at {offset:#x}"))?;
    file.read_exact(buffer)
        .with_context(|| format!("failed reading {what} at {offset:#x}"))
}

fn read_u16(bytes: &[u8], offset: usize, field: &str) -> Result<u16> {
    let value = bytes
        .get(offset..offset + 2)
        .ok_or_else(|| anyhow!("truncated {field}"))?;
    Ok(u16::from_le_bytes([value[0], value[1]]))
}

fn read_u32(bytes: &[u8], offset: usize, field: &str) -> Result<u32> {
    let value = bytes
        .get(offset..offset + 4)
        .ok_or_else(|| anyhow!("truncated {field}"))?;
    Ok(u32::from_le_bytes(
        value.try_into().expect("slice length was checked"),
    ))
}

fn read_u64(bytes: &[u8], offset: usize, field: &str) -> Result<u64> {
    let value = bytes
        .get(offset..offset + 8)
        .ok_or_else(|| anyhow!("truncated {field}"))?;
    Ok(u64::from_le_bytes(
        value.try_into().expect("slice length was checked"),
    ))
}

fn parse_u64_value(value: &str, field: &str) -> Result<u64> {
    let parsed = if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        u64::from_str_radix(hex, 16)
    } else {
        value.parse::<u64>()
    };
    parsed.map_err(|err| anyhow!("invalid {field} '{value}': {err}"))
}

enum PcileechDevice {
    LiveDma,
    MemoryImage(Option<PathBuf>),
}

fn pcileech_file_path(device: &str) -> PcileechDevice {
    let device = device.trim();
    if device.eq_ignore_ascii_case("file") {
        return PcileechDevice::MemoryImage(None);
    }

    if let Some(rest) = strip_prefix_ignore_ascii_case(device, "file://") {
        if rest.is_empty() {
            return PcileechDevice::MemoryImage(None);
        }
        let path = strip_prefix_ignore_ascii_case(rest, "file=").unwrap_or(rest);
        let path = path
            .split_once(",volatile=")
            .map_or(path, |(path, _)| path)
            .trim();
        return PcileechDevice::MemoryImage((!path.is_empty()).then(|| PathBuf::from(path)));
    }

    let path = Path::new(device);
    if path.is_absolute()
        || device.starts_with("./")
        || device.starts_with("../")
        || device.starts_with("\\\\")
        || has_windows_drive_prefix(device)
        || path.is_file()
    {
        PcileechDevice::MemoryImage(Some(path.to_path_buf()))
    } else {
        PcileechDevice::LiveDma
    }
}

fn strip_prefix_ignore_ascii_case<'a>(value: &'a str, prefix: &str) -> Option<&'a str> {
    value
        .get(..prefix.len())
        .filter(|candidate| candidate.eq_ignore_ascii_case(prefix))
        .map(|_| &value[prefix.len()..])
}

fn has_windows_drive_prefix(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(bytes[2], b'\\' | b'/')
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    static TEST_FILE_ID: AtomicU64 = AtomicU64::new(0);

    struct TestFile(PathBuf);

    impl TestFile {
        fn create(bytes: &[u8], extension: &str) -> Self {
            let id = TEST_FILE_ID.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "exhume-memory-source-{}-{id}.{extension}",
                std::process::id()
            ));
            fs::write(&path, bytes).expect("write synthetic memory image");
            Self(path)
        }
    }

    impl Drop for TestFile {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
        }
    }

    #[test]
    fn detects_image_magic() {
        assert_eq!(
            detect_memory_image_format(b"\x7fELF\x02\x01\x01\0"),
            MemoryImageFormat::ElfCore
        );
        assert_eq!(
            detect_memory_image_format(WINDOWS_DUMP64_MAGIC),
            MemoryImageFormat::WindowsCrashDump
        );
        assert_eq!(
            detect_memory_image_format(WINDOWS_DUMP32_MAGIC),
            MemoryImageFormat::WindowsCrashDump
        );
        assert_eq!(
            detect_memory_image_format(b"not a structured dump"),
            MemoryImageFormat::FlatRaw
        );
    }

    #[test]
    fn classifies_connector_descriptors_without_opening_them() {
        let rawmem =
            classify_connector_descriptor(ConnectorKind::Rawmem, "/tmp/memory.raw:base=0x100000")
                .expect("rawmem descriptor");
        assert_eq!(
            rawmem.source,
            ConnectorSourceDescriptor::MemoryImage {
                path: Some(PathBuf::from("/tmp/memory.raw")),
                physical_base: 0x100000,
            }
        );

        let dma = classify_connector_descriptor(ConnectorKind::Pcileech, ":device=FPGA")
            .expect("DMA descriptor");
        assert_eq!(dma.source, ConnectorSourceDescriptor::LiveDma);

        let image =
            classify_connector_descriptor(ConnectorKind::Pcileech, ":device=/tmp/memory.core")
                .expect("file descriptor");
        assert_eq!(
            image.source,
            ConnectorSourceDescriptor::MemoryImage {
                path: Some(PathBuf::from("/tmp/memory.core")),
                physical_base: 0,
            }
        );

        let file_url = classify_connector_descriptor(
            ConnectorKind::Pcileech,
            ":device=\"file:///tmp/memory.core\"",
        )
        .expect("file URL descriptor");
        assert_eq!(
            file_url.source,
            ConnectorSourceDescriptor::MemoryImage {
                path: Some(PathBuf::from("/tmp/memory.core")),
                physical_base: 0,
            }
        );

        let unresolved = classify_connector_descriptor(ConnectorKind::Pcileech, ":device=file")
            .expect("unresolved file descriptor");
        assert_eq!(
            unresolved.source,
            ConnectorSourceDescriptor::MemoryImage {
                path: None,
                physical_base: 0,
            }
        );
    }

    #[test]
    fn inspects_valid_elf64_load_ranges() {
        let bytes = elf64_image(&[(0x1000, 0, 0x1000), (0x2000, 0x3000, 0x1000)]);
        let image = TestFile::create(&bytes, "core");
        let inspection = inspect_memory_image(&image.0).expect("valid ELF core");

        assert!(matches!(
            inspection.identity,
            MemorySourceIdentity::MemoryImage {
                format: MemoryImageFormat::ElfCore,
                ..
            }
        ));
        assert_eq!(
            inspection.readable_ranges,
            vec![
                PhysicalMemoryRange {
                    start: 0,
                    end: 0x1000,
                    source_offset: Some(0x1000),
                },
                PhysicalMemoryRange {
                    start: 0x3000,
                    end: 0x4000,
                    source_offset: Some(0x2000),
                },
            ]
        );
        let scan_ranges = inspection.scan_ranges().expect("Scanflow ranges");
        assert_eq!(scan_ranges.len(), 2);
        assert_eq!(scan_ranges[0].start().to_umem(), 0);
        assert_eq!(scan_ranges[0].end().to_umem(), 0x1000);
        assert_eq!(scan_ranges[1].start().to_umem(), 0x3000);
        assert_eq!(scan_ranges[1].end().to_umem(), 0x4000);
    }

    #[test]
    fn accepts_noncanonical_elf_header_size_like_leechcore() {
        let mut bytes = elf64_image(&[(0x1000, 0, 0x1000)]);
        put_u16(&mut bytes, 52, 8);
        let image = TestFile::create(&bytes, "core");

        let inspection = inspect_memory_image(&image.0)
            .expect("LeechCore-compatible inspection must ignore noncanonical e_ehsize");
        assert!(matches!(
            inspection.identity,
            MemorySourceIdentity::MemoryImage {
                format: MemoryImageFormat::ElfCore,
                ..
            }
        ));
        assert_eq!(inspection.readable_ranges.len(), 1);
    }

    #[test]
    fn rejects_elf_physical_overflow() {
        let mut bytes = elf64_image(&[(0x1000, 0, 0x1000)]);
        put_u64(&mut bytes, 64 + 24, u64::MAX - 0xfff);
        let image = TestFile::create(&bytes, "core");
        let error = inspect_memory_image(&image.0).expect_err("overflow must fail");
        assert!(error.to_string().contains("physical range"));
    }

    #[test]
    fn rejects_elf_file_overflow() {
        let mut bytes = elf64_image(&[(0x1000, 0, 0x1000)]);
        put_u64(&mut bytes, 64 + 8, u64::MAX - 0xfff);
        let image = TestFile::create(&bytes, "core");
        let error = inspect_memory_image(&image.0).expect_err("overflow must fail");
        assert!(error.to_string().contains("file range overflows"));
    }

    #[test]
    fn rejects_overlapping_elf_physical_ranges() {
        let bytes = elf64_image(&[(0x1000, 0, 0x1000), (0x2000, 0, 0x1000)]);
        let image = TestFile::create(&bytes, "core");
        let error = inspect_memory_image(&image.0).expect_err("overlap must fail");
        assert!(format!("{error:#}").contains("overlapping physical ranges"));
    }

    #[test]
    fn rejects_overlapping_elf_file_ranges() {
        let mut bytes = elf64_image(&[(0x1000, 0, 0x1000), (0x2000, 0x2000, 0x1000)]);
        put_u64(&mut bytes, 64 + 56 + 8, 0x1000);
        let image = TestFile::create(&bytes, "core");
        let error = inspect_memory_image(&image.0).expect_err("overlap must fail");
        assert!(format!("{error:#}").contains("overlapping image ranges"));
    }

    #[test]
    fn rejects_elf_ranges_that_are_not_in_descriptor_order() {
        let bytes = elf64_image(&[(0x1000, 0x3000, 0x1000), (0x2000, 0, 0x1000)]);
        let image = TestFile::create(&bytes, "core");
        let error = inspect_memory_image(&image.0).expect_err("unsorted map must fail");
        assert!(format!("{error:#}").contains("ascending physical-address order"));
    }

    #[test]
    fn rejects_elf_program_headers_outside_leechcore_header_window() {
        let mut bytes = elf64_image(&[(0x1000, 0, 0x1000)]);
        put_u64(&mut bytes, 32, 0x2000);
        let image = TestFile::create(&bytes, "core");
        let error = inspect_memory_image(&image.0).expect_err("late table must fail");
        assert!(format!("{error:#}").contains("first 0x2000 bytes"));
    }

    #[test]
    fn parses_windows_x64_page_count_as_u32_and_preserves_ranges() {
        let bytes = windows_x64_full_dump(&[(0, 1), (3, 1)], 0xdead_beef);
        let image = TestFile::create(&bytes, "dmp");
        let inspection = inspect_memory_image(&image.0).expect("valid Windows full dump");
        assert!(matches!(
            inspection.identity,
            MemorySourceIdentity::MemoryImage {
                format: MemoryImageFormat::WindowsCrashDump,
                ..
            }
        ));
        assert_eq!(
            inspection.readable_ranges,
            vec![
                PhysicalMemoryRange {
                    start: 0,
                    end: 0x1000,
                    source_offset: Some(0x2000),
                },
                PhysicalMemoryRange {
                    start: 0x3000,
                    end: 0x4000,
                    source_offset: Some(0x3000),
                }
            ]
        );
    }

    #[test]
    fn rejects_unsorted_windows_physical_runs() {
        let bytes = windows_x64_full_dump(&[(3, 1), (0, 1)], 0);
        let image = TestFile::create(&bytes, "dmp");
        let error = inspect_memory_image(&image.0).expect_err("unsorted map must fail");
        assert!(format!("{error:#}").contains("ascending physical-address order"));
    }

    #[test]
    fn rawmem_rejects_elf_instead_of_identity_mapping_it() {
        let mut bytes = elf64_image(&[(0x1000, 0, 0x1000)]);
        put_u16(&mut bytes, 52, 8);
        let image = TestFile::create(&bytes, "core");
        let descriptor = classify_connector_descriptor(
            ConnectorKind::Rawmem,
            image.0.to_str().expect("UTF-8 test path"),
        )
        .expect("descriptor");
        let error = inspect_descriptor_image(&descriptor).expect_err("rawmem must reject ELF");
        let message = format!("{error:#}");
        assert!(message.contains("rawmem"));
        assert!(message.contains("ElfCore"));

        let options = crate::ConnectorOptions {
            connector: image.0.display().to_string(),
            kind: ConnectorKind::Rawmem,
            os_kind: crate::OsKind::Windows,
            linux_profile: None,
        };
        let open_error = options
            .open()
            .err()
            .expect("opening ELF through rawmem must fail before connector creation");
        assert!(format!("{open_error:#}").contains("rawmem cannot open ElfCore"));
    }

    #[test]
    fn validates_flat_raw_base_overflow() {
        let image = TestFile::create(&[0u8; 32], "raw");
        let descriptor = classify_connector_descriptor(
            ConnectorKind::Rawmem,
            &format!("{}:base={}", image.0.display(), u64::MAX - 15),
        )
        .expect("descriptor");
        let error = inspect_descriptor_image(&descriptor).expect_err("range must overflow");
        assert!(
            error
                .to_string()
                .contains("physical memory range overflows")
        );
    }

    #[test]
    fn unresolved_pcileech_file_descriptor_fails_clearly() {
        let descriptor = classify_connector_descriptor(ConnectorKind::Pcileech, ":device=file")
            .expect("descriptor");
        let error = inspect_descriptor_image(&descriptor).expect_err("path is required");
        assert!(
            error
                .to_string()
                .contains("does not provide an inspectable path")
        );
    }

    fn elf64_image(segments: &[(u64, u64, u64)]) -> Vec<u8> {
        let program_offset = 64usize;
        let entry_size = 56usize;
        let table_end = program_offset + entry_size * segments.len();
        let file_end = segments
            .iter()
            .map(|(offset, _, length)| offset + length)
            .max()
            .unwrap_or(table_end as u64)
            .max(table_end as u64);
        let mut bytes = vec![0u8; usize::try_from(file_end).expect("synthetic size")];

        bytes[..4].copy_from_slice(ELF_MAGIC);
        bytes[4] = 2;
        bytes[5] = 1;
        bytes[6] = 1;
        put_u16(&mut bytes, 16, ELF_ET_CORE);
        put_u32(&mut bytes, 20, ELF_CURRENT_VERSION);
        put_u64(&mut bytes, 32, program_offset as u64);
        put_u16(&mut bytes, 52, 64);
        put_u16(&mut bytes, 54, entry_size as u16);
        put_u16(&mut bytes, 56, segments.len() as u16);

        for (index, (source_offset, physical_start, length)) in segments.iter().enumerate() {
            let entry = program_offset + index * entry_size;
            put_u32(&mut bytes, entry, ELF_PT_LOAD);
            put_u64(&mut bytes, entry + 8, *source_offset);
            put_u64(&mut bytes, entry + 24, *physical_start);
            put_u64(&mut bytes, entry + 32, *length);
            put_u64(&mut bytes, entry + 40, *length);
            put_u64(&mut bytes, entry + 48, PAGE_SIZE);
        }

        bytes
    }

    fn windows_x64_full_dump(runs: &[(u64, u64)], reserved: u32) -> Vec<u8> {
        let pages = runs.iter().map(|(_, count)| count).sum::<u64>();
        let mut bytes = vec![0u8; 0x2000 + usize::try_from(pages * PAGE_SIZE).unwrap()];
        bytes[..8].copy_from_slice(WINDOWS_DUMP64_MAGIC);
        put_u32(&mut bytes, 0x30, 0x8664);
        put_u32(&mut bytes, 0xf98, 1);
        put_u32(&mut bytes, 0x88, runs.len() as u32);
        put_u32(&mut bytes, 0x90, pages as u32);
        put_u32(&mut bytes, 0x94, reserved);
        for (index, (base_page, page_count)) in runs.iter().enumerate() {
            let offset = 0x98 + index * 16;
            put_u64(&mut bytes, offset, *base_page);
            put_u64(&mut bytes, offset + 8, *page_count);
        }
        bytes
    }

    fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }
}
