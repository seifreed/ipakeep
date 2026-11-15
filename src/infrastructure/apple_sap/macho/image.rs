//! Mach-O arm64e image preparation, relocation and guest layout.

use std::collections::{BTreeSet, HashMap};
use std::fmt::Display;

use sha2::{Digest, Sha256};

use super::cache::{Preparation, PreparationCache};
use super::chained::{ChainedFixups, bits};
use super::dyld_info::{BindStream, FixupContext, parse_binds, parse_rebases};
use super::error::{MachoError, MachoResult};
use super::fat::arm64_slice;
use super::layout::{Layout, LinkeditRange, Section, Segment, le64_at};
use super::pac::{apply_patches, strip_range};
use super::relocation::Relocation;
use super::symbols::{Symbol, TrieExport, equal_fold, parse_export_trie, parse_symtab};

const PAGE_SIZE: u64 = 0x1000;
const MAX_IMAGE_SPAN: u64 = 1 << 30;
const POINTER_LEN: usize = 8;
const POINTER_SIZE: u64 = POINTER_LEN as u64;
const KERNEL_FIXUP_STRIDE: u64 = 4;
const KERNEL_CACHE_TARGET_BITS: u32 = 30;
const KERNEL_CACHE_LEVEL_SHIFT: u32 = 30;
const KERNEL_CACHE_LEVEL_BITS: u32 = 2;
const PAGEZERO: &str = "__PAGEZERO";
const TEXT: &str = "__TEXT";
const TEXT_EXEC: &str = "__TEXT_EXEC";
const LINKEDIT: &str = "__LINKEDIT";

/// A page-aligned guest range that must be mapped before writing segments.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryRegion {
    /// Page-aligned guest address.
    pub address: u64,
    /// Page-aligned size in bytes.
    pub size: u64,
}

/// File-backed bytes of one segment at its guest address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SegmentData<'a> {
    /// Segment name.
    pub name: &'a str,
    /// Guest address the bytes are written to (not necessarily page aligned).
    pub address: u64,
    /// Virtual size of the segment (bytes past `data.len()` are zero-filled).
    pub memory_size: u64,
    /// Initial VM protection declared by the image (`VM_PROT_*`).
    pub protection: u32,
    /// Prepared (PAC-stripped, relocated) file bytes.
    pub data: &'a [u8],
}

/// Everything needed to place a prepared image into guest memory: map every
/// region (upstream maps them read/write/execute), then write every segment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadPlan<'a> {
    /// Merged, page-aligned regions sorted by address.
    pub regions: Vec<MemoryRegion>,
    /// Segment contents in load-command order.
    pub segments: Vec<SegmentData<'a>>,
}

/// An arm64e Mach-O image prepared for emulation.
///
/// Opening strips pointer authentication from instruction sections and
/// decodes fixups; one of [`MachImage::relocate`] or
/// [`MachImage::prepare_prelinked`] must run before [`MachImage::load_plan`].
#[derive(Debug, Clone)]
pub struct MachImage {
    name: String,
    data: Vec<u8>,
    base: u64,
    segments: Vec<Segment>,
    sections: Vec<Section>,
    has_symtab: bool,
    symbols: Vec<Symbol>,
    trie_exports: Vec<TrieExport>,
    relocations: Vec<Relocation>,
    loaded_base: Option<u64>,
}

impl MachImage {
    /// Opens `input` (thin or universal) and prepares it without caching.
    ///
    /// # Errors
    /// Fails when the input is not a well-formed arm64 Mach-O or its fixups are unsupported.
    pub fn open(name: &str, input: &[u8]) -> MachoResult<Self> {
        Self::open_with_cache(name, input, None)
    }

    /// Opens `input`, reusing (and populating) `cache` for the immutable
    /// preparation: instruction patches, decoded fixups and symbols.
    ///
    /// # Errors
    /// Same as [`MachImage::open`]; cache failures only disable caching.
    pub fn open_with_cache(
        name: &str,
        input: &[u8],
        cache: Option<&PreparationCache>,
    ) -> MachoResult<Self> {
        let slice = arm64_slice(input)?;
        let mut data = slice.to_vec();
        let layout = Layout::parse(name, &data)?;
        validate_segments(name, &layout.segments, data.len())?;
        let key: [u8; 32] = Sha256::digest(&data).into();
        let cached = cache.and_then(|cache| cache.load(&key));
        let preparation = if let Some(preparation) = cached {
            apply_patches(&mut data, &preparation.patches);
            preparation
        } else {
            let preparation = prepare(name, &mut data, &layout)?;
            if let Some(cache) = cache {
                cache.store(&key, &preparation);
            }
            preparation
        };
        let trie_exports = trie_exports(&data, &layout);
        Ok(Self {
            name: name.to_owned(),
            base: layout.base(),
            segments: layout.segments,
            sections: layout.sections,
            has_symtab: preparation.has_symtab,
            symbols: preparation.symbols,
            trie_exports,
            relocations: preparation.relocations,
            loaded_base: None,
            data,
        })
    }

    /// Image name used in diagnostics.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Preferred load address (the `__TEXT` segment address, else 0).
    pub fn base(&self) -> u64 {
        self.base
    }

    /// Guest base chosen by the last relocation, if any.
    pub fn loaded_base(&self) -> Option<u64> {
        self.loaded_base
    }

    /// Segments in load-command order, at their preferred addresses.
    pub fn segments(&self) -> &[Segment] {
        &self.segments
    }

    /// The image's `nlist_64` symbol table in file order.
    pub fn symbols(&self) -> &[Symbol] {
        &self.symbols
    }

    /// Decoded fixups in the order they are applied.
    pub fn relocations(&self) -> &[Relocation] {
        &self.relocations
    }

    /// Distinct symbol names the image binds to, sorted.
    pub fn imports(&self) -> BTreeSet<&str> {
        self.relocations
            .iter()
            .filter_map(|relocation| match relocation {
                Relocation::Bind { symbol, .. } => Some(symbol.as_str()),
                Relocation::Rebase { .. } => None,
            })
            .collect()
    }

    /// Preferred-address `[start, end)` ranges of executable sections.
    pub fn instruction_ranges(&self) -> Vec<(u64, u64)> {
        self.sections
            .iter()
            .filter(|section| section.has_instructions())
            .map(|section| (section.address, section.address.wrapping_add(section.size)))
            .collect()
    }

    /// Prepared thin-image bytes (after PAC stripping and any relocation).
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Address of `symbol` when the image is loaded at `load_base`.
    ///
    /// Matches go-macho: the first case-insensitive symbol-table match wins,
    /// then the classic dyld-info export trie.
    ///
    /// # Errors
    /// Fails when the symbol is missing, precedes the image base or overflows.
    pub fn export(&self, symbol: &str, load_base: u64) -> MachoResult<u64> {
        let address = self.find_symbol_address(symbol)?;
        let offset = address.checked_sub(self.base).ok_or_else(|| {
            MachoError::malformed(&self.name, format!("symbol {symbol} precedes image base"))
        })?;
        load_base
            .checked_add(offset)
            .ok_or_else(|| MachoError::overflow(&self.name, format!("symbol {symbol}")))
    }

    fn find_symbol_address(&self, symbol: &str) -> MachoResult<u64> {
        let not_found = || MachoError::SymbolNotFound {
            image: self.name.clone(),
            symbol: symbol.to_owned(),
        };
        if !self.has_symtab {
            return Err(not_found());
        }
        let from_symtab = self
            .symbols
            .iter()
            .find(|entry| equal_fold(&entry.name, symbol));
        if let Some(entry) = from_symtab {
            return Ok(entry.value);
        }
        self.trie_exports
            .iter()
            .find(|entry| equal_fold(&entry.name, symbol))
            .map(|entry| entry.address)
            .ok_or_else(not_found)
    }

    /// Applies every decoded rebase and bind for a guest base of `load_base`.
    /// `resolve` is called once per bind, in fixup order.
    ///
    /// # Errors
    /// Fails when already relocated, on resolver failure, or on address overflow.
    pub fn relocate<R, E>(&mut self, load_base: u64, mut resolve: R) -> MachoResult<()>
    where
        R: FnMut(&str) -> Result<u64, E>,
        E: Display,
    {
        self.ensure_unrelocated()?;
        let relocations = std::mem::take(&mut self.relocations);
        let result = relocations
            .iter()
            .try_for_each(|relocation| self.apply(relocation, load_base, &mut resolve));
        self.relocations = relocations;
        result?;
        self.loaded_base = Some(load_base);
        Ok(())
    }

    fn apply<R, E>(
        &mut self,
        relocation: &Relocation,
        load_base: u64,
        resolve: &mut R,
    ) -> MachoResult<()>
    where
        R: FnMut(&str) -> Result<u64, E>,
        E: Display,
    {
        let value = match relocation {
            Relocation::Rebase { offset, target } => {
                load_base.checked_add(*target).ok_or_else(|| {
                    MachoError::overflow(
                        &self.name,
                        format!("chained rebase at {offset:#x} with target {target:#x}"),
                    )
                })?
            }
            Relocation::Bind { symbol, addend, .. } => {
                let address = self.resolve_symbol(symbol, resolve)?;
                address.checked_add_signed(*addend).ok_or_else(|| {
                    MachoError::overflow(&self.name, format!("addend for {symbol}"))
                })?
            }
        };
        self.put_pointer(relocation.offset(), value)
    }

    fn resolve_symbol<R, E>(&self, symbol: &str, resolve: &mut R) -> MachoResult<u64>
    where
        R: FnMut(&str) -> Result<u64, E>,
        E: Display,
    {
        resolve(symbol).map_err(|error| MachoError::Resolve {
            image: self.name.clone(),
            symbol: symbol.to_owned(),
            reason: error.to_string(),
        })
    }

    /// Prepares an image extracted from a dyld shared cache: it stays at its
    /// preferred address and every data pointer equal to a key of `external`
    /// is replaced by the resolved address of the mapped import name.
    ///
    /// # Errors
    /// Fails when already relocated or when the resolver fails.
    pub fn prepare_prelinked<R, E>(
        &mut self,
        external: &HashMap<u64, String>,
        mut resolve: R,
    ) -> MachoResult<()>
    where
        R: FnMut(&str) -> Result<u64, E>,
        E: Display,
    {
        self.ensure_unrelocated()?;
        let mut ordered: Vec<(&u64, &String)> = external.iter().collect();
        ordered.sort();
        let mut patched = HashMap::with_capacity(ordered.len());
        for (address, symbol) in ordered {
            patched.insert(*address, self.resolve_symbol(symbol, &mut resolve)?);
        }
        if !patched.is_empty() {
            self.patch_prelinked_pointers(&patched)?;
        }
        self.loaded_base = Some(self.base);
        Ok(())
    }

    fn patch_prelinked_pointers(&mut self, patched: &HashMap<u64, u64>) -> MachoResult<()> {
        for (start, end) in self.pointer_scan_ranges(&[TEXT, LINKEDIT], POINTER_SIZE) {
            let mut offset = start;
            while offset + POINTER_SIZE <= end {
                if let Some(&value) = patched.get(&self.pointer_at(offset)) {
                    self.put_pointer(offset, value)?;
                }
                offset += POINTER_SIZE;
            }
        }
        Ok(())
    }

    /// File ranges scanned for embedded pointers, aligned so each candidate's
    /// address is a multiple of `alignment`.
    fn pointer_scan_ranges(&self, excluded: &[&str], alignment: u64) -> Vec<(u64, u64)> {
        self.segments
            .iter()
            .filter(|segment| {
                !excluded.contains(&segment.name.as_str()) && segment.file_size >= POINTER_SIZE
            })
            .map(|segment| {
                let remainder = segment.address % alignment;
                let skip = if remainder == 0 {
                    0
                } else {
                    alignment - remainder
                };
                (
                    segment.file_offset + skip,
                    segment.file_offset + segment.file_size,
                )
            })
            .collect()
    }

    /// Relocates authenticated pointers embedded in an executable extracted
    /// from a kernel collection whose collection base is `kernel_base`.
    ///
    /// # Errors
    /// Fails on resolver failure or address overflow.
    pub fn relocate_kernel_cache_pointers<R, E>(
        &mut self,
        load_base: u64,
        kernel_base: u64,
        mut resolve: R,
    ) -> MachoResult<()>
    where
        R: FnMut(&str) -> Result<u64, E>,
        E: Display,
    {
        let external = self.external_symbols();
        for (start, end) in
            self.pointer_scan_ranges(&[TEXT, TEXT_EXEC, LINKEDIT], KERNEL_FIXUP_STRIDE)
        {
            let mut offset = start;
            while offset + POINTER_SIZE <= end {
                let target = KernelPointer {
                    load_base,
                    kernel_base,
                    offset,
                };
                if let Some(value) = self.kernel_pointer_value(target, &external, &mut resolve)? {
                    self.put_pointer(offset, value)?;
                }
                offset += KERNEL_FIXUP_STRIDE;
            }
        }
        Ok(())
    }

    fn external_symbols(&self) -> HashMap<u64, String> {
        self.symbols
            .iter()
            .filter(|symbol| symbol.value != 0 && !self.contains_address(symbol.value))
            .map(|symbol| (symbol.value, symbol.name.clone()))
            .collect()
    }

    fn kernel_pointer_value<R, E>(
        &self,
        pointer: KernelPointer,
        external: &HashMap<u64, String>,
        resolve: &mut R,
    ) -> MachoResult<Option<u64>>
    where
        R: FnMut(&str) -> Result<u64, E>,
        E: Display,
    {
        let raw = self.pointer_at(pointer.offset);
        let target = bits(raw, 0, KERNEL_CACHE_TARGET_BITS);
        if bits(raw, KERNEL_CACHE_LEVEL_SHIFT, KERNEL_CACHE_LEVEL_BITS) != 0 || target == 0 {
            return Ok(None);
        }
        let Some(original) = pointer.kernel_base.checked_add(target) else {
            return Ok(None);
        };
        if self.contains_address(original) {
            let relocated = pointer
                .load_base
                .checked_add(original.wrapping_sub(self.base));
            return relocated.map(Some).ok_or_else(|| {
                MachoError::overflow(
                    &self.name,
                    format!("kernel-cache pointer at {:#x}", pointer.offset),
                )
            });
        }
        match external.get(&original) {
            Some(symbol) => self.resolve_symbol(symbol, resolve).map(Some),
            None => Ok(None),
        }
    }

    fn contains_address(&self, address: u64) -> bool {
        self.segments
            .iter()
            .any(|segment| address >= segment.address && address - segment.address < segment.size)
    }

    /// Guest layout of the relocated image.
    ///
    /// # Errors
    /// Fails before relocation, or when segments precede the base or overflow.
    pub fn load_plan(&self) -> MachoResult<LoadPlan<'_>> {
        let loaded_base = self.loaded_base.ok_or_else(|| MachoError::State {
            image: self.name.clone(),
            reason: "image must be relocated before loading",
        })?;
        let regions = self.memory_regions(loaded_base)?;
        let mut segments = Vec::new();
        for segment in self.loadable().filter(|segment| segment.file_size != 0) {
            segments.push(SegmentData {
                name: &segment.name,
                address: self.guest_address(segment, loaded_base)?,
                memory_size: segment.size,
                protection: segment.initial_protection,
                data: self.file_bytes(segment)?,
            });
        }
        Ok(LoadPlan { regions, segments })
    }

    fn loadable(&self) -> impl Iterator<Item = &Segment> {
        self.segments
            .iter()
            .filter(|segment| segment.name != PAGEZERO)
    }

    fn guest_address(&self, segment: &Segment, loaded_base: u64) -> MachoResult<u64> {
        let offset = segment.address.checked_sub(self.base).ok_or_else(|| {
            MachoError::malformed(
                &self.name,
                format!("segment {} precedes image base", segment.name),
            )
        })?;
        loaded_base
            .checked_add(offset)
            .ok_or_else(|| MachoError::overflow(&self.name, format!("segment {}", segment.name)))
    }

    fn memory_regions(&self, loaded_base: u64) -> MachoResult<Vec<MemoryRegion>> {
        let mut ranges = Vec::new();
        for segment in self.loadable().filter(|segment| segment.size != 0) {
            let address = self.guest_address(segment, loaded_base)?;
            let end = address
                .checked_add(segment.size)
                .and_then(|end| end.checked_add(PAGE_SIZE - 1))
                .ok_or_else(|| {
                    MachoError::overflow(&self.name, format!("segment {} range", segment.name))
                })?;
            ranges.push((address - address % PAGE_SIZE, end & !(PAGE_SIZE - 1)));
        }
        if ranges.is_empty() {
            return Err(MachoError::malformed(&self.name, "no loadable segments"));
        }
        let regions = merge_ranges(ranges);
        let mapped = regions
            .iter()
            .fold(0u64, |total, region| total.saturating_add(region.size));
        if mapped > MAX_IMAGE_SPAN {
            return Err(MachoError::malformed(
                &self.name,
                "mapped segments make the image too large",
            ));
        }
        Ok(regions)
    }

    fn ensure_unrelocated(&self) -> MachoResult<()> {
        if self.loaded_base.is_some() {
            return Err(MachoError::State {
                image: self.name.clone(),
                reason: "image is already relocated",
            });
        }
        Ok(())
    }

    fn file_bytes(&self, segment: &Segment) -> MachoResult<&[u8]> {
        let start = usize::try_from(segment.file_offset).ok();
        let length = usize::try_from(segment.file_size).ok();
        let range = start
            .zip(length)
            .and_then(|(start, length)| Some(start..start.checked_add(length)?));
        range.and_then(|range| self.data.get(range)).ok_or_else(|| {
            MachoError::malformed(
                &self.name,
                format!("segment {} data exceeds image", segment.name),
            )
        })
    }

    fn pointer_at(&self, offset: u64) -> u64 {
        le64_at(&self.data, offset).unwrap_or(0)
    }

    fn put_pointer(&mut self, offset: u64, value: u64) -> MachoResult<()> {
        let start = usize::try_from(offset).ok();
        let range = start.and_then(|start| Some(start..start.checked_add(POINTER_LEN)?));
        match range.and_then(|range| self.data.get_mut(range)) {
            Some(slot) => {
                slot.copy_from_slice(&value.to_le_bytes());
                Ok(())
            }
            None => Err(MachoError::malformed(
                &self.name,
                format!("fixup at {offset:#x} exceeds image"),
            )),
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct KernelPointer {
    load_base: u64,
    kernel_base: u64,
    offset: u64,
}

fn merge_ranges(mut ranges: Vec<(u64, u64)>) -> Vec<MemoryRegion> {
    ranges.sort_by_key(|range| range.0);
    let mut merged: Vec<(u64, u64)> = Vec::with_capacity(ranges.len());
    for (start, end) in ranges {
        match merged.last_mut() {
            Some(last) if start <= last.1 => last.1 = last.1.max(end),
            _ => merged.push((start, end)),
        }
    }
    merged
        .into_iter()
        .map(|(address, end)| MemoryRegion {
            address,
            size: end - address,
        })
        .collect()
}

fn validate_segments(name: &str, segments: &[Segment], length: usize) -> MachoResult<()> {
    for segment in segments {
        if segment.file_size > segment.size {
            return Err(MachoError::malformed(
                name,
                format!("segment {} file data exceeds its memory size", segment.name),
            ));
        }
        if segment.address.checked_add(segment.size).is_none() {
            return Err(MachoError::overflow(
                name,
                format!("segment {} address range", segment.name),
            ));
        }
        let end = segment.file_offset.checked_add(segment.file_size);
        if end.is_none_or(|end| end > length as u64) {
            return Err(MachoError::malformed(
                name,
                format!("segment {} data exceeds image", segment.name),
            ));
        }
    }
    Ok(())
}

/// Strips PAC, parses symbols and decodes fixups (the cacheable work).
fn prepare(name: &str, data: &mut [u8], layout: &Layout) -> MachoResult<Preparation> {
    let symbols = match layout.symtab {
        Some(command) => parse_symtab(name, data, command)?,
        None => Vec::new(),
    };
    let patches = strip_pointer_authentication(name, data, &layout.sections)?;
    let context = FixupContext {
        image: name,
        data,
        segments: &layout.segments,
        base: layout.base(),
    };
    let relocations = match layout.chained_fixups {
        Some(range) => {
            let payload = linkedit(name, data, range)?;
            ChainedFixups::parse(&context, payload)?.relocations(&context)?
        }
        None => dyld_info_relocations(&context, layout)?,
    };
    Ok(Preparation {
        has_symtab: layout.symtab.is_some(),
        symbols,
        patches,
        relocations,
    })
}

fn strip_pointer_authentication(
    name: &str,
    data: &mut [u8],
    sections: &[Section],
) -> MachoResult<Vec<super::pac::InstructionPatch>> {
    let mut ranges = Vec::new();
    for section in sections.iter().filter(|section| section.has_instructions()) {
        let start = section.offset as usize;
        let end = usize::try_from(section.size)
            .ok()
            .and_then(|size| start.checked_add(size))
            .filter(|&end| end <= data.len());
        let end = end.ok_or_else(|| {
            MachoError::malformed(
                name,
                format!("instruction section {} exceeds image", section.name),
            )
        })?;
        ranges.push((start, end));
    }
    let mut patches = Vec::new();
    for (start, end) in ranges {
        strip_range(data, start, end, &mut patches);
    }
    Ok(patches)
}

fn linkedit<'a>(name: &str, data: &'a [u8], range: LinkeditRange) -> MachoResult<&'a [u8]> {
    let start = range.offset as usize;
    data.get(start..start + range.size as usize)
        .ok_or_else(|| MachoError::malformed(name, "linkedit data exceeds image"))
}

fn dyld_info_relocations(
    context: &FixupContext<'_>,
    layout: &Layout,
) -> MachoResult<Vec<Relocation>> {
    let Some(info) = layout.dyld_info() else {
        return Ok(Vec::new());
    };
    let stream = |range: LinkeditRange| linkedit(context.image, context.data, range);
    let mut relocations = Vec::new();
    if info.rebase.size > 0 {
        relocations.extend(parse_rebases(context, stream(info.rebase)?)?);
    }
    for (range, kind) in [
        (info.bind, BindStream::Eager),
        (info.weak_bind, BindStream::Eager),
        (info.lazy_bind, BindStream::Lazy),
    ] {
        if range.size > 0 {
            relocations.extend(parse_binds(context, stream(range)?, kind)?);
        }
    }
    Ok(relocations)
}

fn trie_exports(data: &[u8], layout: &Layout) -> Vec<TrieExport> {
    let Some(info) = layout.dyld_info() else {
        return Vec::new();
    };
    let start = info.export.offset as usize;
    data.get(start..start + info.export.size as usize)
        .filter(|trie| !trie.is_empty())
        .and_then(|trie| parse_export_trie(trie, layout.base()))
        .unwrap_or_default()
}
