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
            let image_offset = original.wrapping_sub(self.base);
            let relocated = pointer.load_base.checked_add(image_offset);
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

#[cfg(test)]
mod tests {
    use std::convert::Infallible;
    use std::fs;
    use std::path::PathBuf;

    use super::*;
    use crate::infrastructure::apple_sap::macho::chained::format;
    use crate::infrastructure::apple_sap::macho::layout::le32;
    use crate::infrastructure::apple_sap::macho::test_support::*;

    const LOAD: u64 = 0x2_0000_0000;
    const MALLOC: u64 = 0x5000;

    fn found(symbol: &str) -> Result<u64, &'static str> {
        if symbol.is_empty() {
            Err("empty symbol name")
        } else {
            Ok(MALLOC)
        }
    }

    fn missing(_: &str) -> Result<u64, &'static str> {
        Err("no such symbol")
    }

    fn pointer(image: &MachImage, offset: usize) -> u64 {
        le64_at(image.data(), offset as u64).unwrap_or_default()
    }

    fn open(input: &[u8]) -> MachImage {
        MachImage::open("test", input).unwrap()
    }

    fn open_error(input: &[u8]) -> MachoError {
        MachImage::open("test", input).unwrap_err()
    }

    /// Standard image whose `__DATA` holds a userland rebase chained to a bind.
    fn chained_image() -> Vec<u8> {
        let starts = ChainStarts::single(format::ARM64E_USERLAND, 0x10);
        let payload = chained_payload(
            &[None, None, Some(starts), None],
            ImportFormat::Addend,
            &[("_malloc", 8)],
        );
        MachOBuilder::standard()
            .chained_fixups(LINKEDIT_AT, payload.len())
            .bytes(LINKEDIT_AT, &payload)
            .pointer(DATA_AT + 0x10, 0x1040 | (1 << 51))
            .pointer(DATA_AT + 0x18, 1 << 62)
            .build()
    }

    fn fat(thin: &[u8], subtype: u32) -> Vec<u8> {
        let offset = 0x20u32;
        let mut data = Vec::new();
        for value in [
            0xcafe_babe,
            1,
            CPU_TYPE_ARM64,
            subtype,
            offset,
            u32_of(thin.len()),
            0,
        ] {
            data.extend_from_slice(&u32::to_be_bytes(value));
        }
        data.resize(offset as usize, 0);
        data.extend_from_slice(thin);
        data
    }

    fn temporary_cache(tag: &str) -> (PathBuf, PreparationCache) {
        let directory =
            std::env::temp_dir().join(format!("ipakeep-macho-image-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&directory);
        let cache = PreparationCache::new(&directory);
        (directory, cache)
    }

    #[test]
    fn open_strips_pointer_authentication_and_reports_layout() {
        let image = open(&MachOBuilder::standard().build());
        assert_eq!(image.name(), "test");
        assert_eq!(image.base(), BASE);
        assert_eq!(image.loaded_base(), None);
        let names: Vec<&str> = image.segments().iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, ["__PAGEZERO", "__TEXT", "__DATA", "__LINKEDIT"]);
        assert_eq!(image.symbols(), []);
        assert_eq!(image.relocations(), []);
        assert!(image.imports().is_empty());
        assert_eq!(
            image.instruction_ranges(),
            vec![(BASE + 0x800, BASE + 0x808)]
        );
        assert_eq!(le32(image.data(), TEXT_SECTION), Some(NOP));
        assert_eq!(le32(image.data(), TEXT_SECTION + 4), Some(RET));
    }

    #[test]
    fn open_selects_the_arm64e_slice_of_a_universal_binary() {
        let thin = MachOBuilder::standard().build();
        let image = open(&fat(&thin, CPU_SUBTYPE_ARM64E));
        assert_eq!(image.data().len(), thin.len());
        assert_eq!(image.base(), BASE);
        assert!(matches!(
            open_error(&fat(&thin, 0)),
            MachoError::MissingArm64e
        ));
        assert!(matches!(
            open_error(&[0u8; 64]),
            MachoError::NotArm64 { .. }
        ));
    }

    #[test]
    fn relocate_applies_chained_rebases_and_binds_then_loads() {
        let mut image = open(&chained_image());
        assert_eq!(
            image.relocations(),
            [
                Relocation::Rebase {
                    offset: 0x1010,
                    target: 0x1040
                },
                Relocation::Bind {
                    offset: 0x1018,
                    symbol: "_malloc".to_owned(),
                    addend: 8
                }
            ]
        );
        assert_eq!(image.imports().into_iter().collect::<Vec<_>>(), ["_malloc"]);
        let mut requested = Vec::new();
        image
            .relocate(LOAD, |symbol: &str| {
                requested.push(symbol.to_owned());
                found(symbol)
            })
            .unwrap();
        assert_eq!(requested, ["_malloc"]);
        assert_eq!(image.loaded_base(), Some(LOAD));
        assert_eq!(pointer(&image, DATA_AT + 0x10), LOAD + 0x1040);
        assert_eq!(pointer(&image, DATA_AT + 0x18), MALLOC + 8);
        let plan = image.load_plan().unwrap();
        assert_eq!(
            plan.regions,
            [MemoryRegion {
                address: LOAD,
                size: 0x3000
            }]
        );
        let names: Vec<&str> = plan.segments.iter().map(|s| s.name).collect();
        assert_eq!(names, ["__TEXT", "__DATA", "__LINKEDIT"]);
        let data = plan.segments[1];
        assert_eq!(data.address, LOAD + 0x1000);
        assert_eq!(data.memory_size, 0x1000);
        assert_eq!(data.protection, PROT_RW);
        assert_eq!(data.data, &image.data()[DATA_AT..DATA_AT + 0x1000]);
    }

    #[test]
    fn relocation_happens_only_once() {
        let mut image = open(&chained_image());
        image.relocate(LOAD, found).unwrap();
        let again = image.relocate(LOAD, found).unwrap_err();
        assert!(again.to_string().contains("already relocated"));
        let prelinked = image.prepare_prelinked(&HashMap::new(), found);
        assert!(matches!(prelinked, Err(MachoError::State { .. })));
    }

    #[test]
    fn relocation_failures_leave_the_image_unrelocated() {
        let mut image = open(&chained_image());
        let rebase = image.relocate(u64::MAX, found).unwrap_err();
        assert!(matches!(rebase, MachoError::Overflow { .. }));
        assert_eq!(image.relocations().len(), 2);
        assert_eq!(image.loaded_base(), None);
        let Err(MachoError::Resolve { symbol, reason, .. }) = image.relocate(LOAD, missing) else {
            panic!("expected a resolver failure");
        };
        assert_eq!(
            (symbol.as_str(), reason.as_str()),
            ("_malloc", "no such symbol")
        );
        let addend = image.relocate(LOAD, |_: &str| Ok::<u64, Infallible>(u64::MAX));
        assert!(
            addend
                .unwrap_err()
                .to_string()
                .contains("addend for _malloc")
        );
        image.data.truncate(DATA_AT + 0x14);
        let truncated = image.relocate(LOAD, found).unwrap_err();
        assert!(truncated.to_string().contains("exceeds image"));
        assert_eq!(image.loaded_base(), None);
    }

    #[test]
    fn preparation_cache_is_populated_then_reused() {
        let input = chained_image();
        let (directory, cache) = temporary_cache("reuse");
        let fresh = MachImage::open_with_cache("c", &input, Some(&cache)).unwrap();
        assert_eq!(fs::read_dir(&directory).map(Iterator::count).ok(), Some(1));
        let cached = MachImage::open_with_cache("c", &input, Some(&cache)).unwrap();
        assert_eq!(cached.data(), fresh.data());
        assert_eq!(cached.relocations(), fresh.relocations());
        assert_eq!(le32(cached.data(), TEXT_SECTION), Some(NOP));
        let _ = fs::remove_dir_all(&directory);
    }

    #[test]
    fn cached_preparations_are_trusted_over_the_image() {
        let input = MachOBuilder::standard().build();
        let (directory, cache) = temporary_cache("trusted");
        let key: [u8; 32] = Sha256::digest(&input).into();
        let preparation = Preparation {
            has_symtab: false,
            symbols: Vec::new(),
            patches: Vec::new(),
            relocations: vec![Relocation::Rebase {
                offset: 0x10_0000,
                target: 0,
            }],
        };
        cache.store(&key, &preparation);
        let mut image = MachImage::open_with_cache("c", &input, Some(&cache)).unwrap();
        assert_eq!(le32(image.data(), TEXT_SECTION), Some(PACIBSP));
        let error = image.relocate(LOAD, found).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("fixup at 0x100000 exceeds image")
        );
        let _ = fs::remove_dir_all(&directory);
    }

    fn symbol_image(with_symtab: bool) -> Vec<u8> {
        let (table, strings) = symbol_table(&[
            ("_Alpha", 0x0f, BASE + 0x800),
            ("_low", 0x0f, 0x10),
            ("_ext", 0x01, 0x9_0000_0000),
        ]);
        let trie = export_trie(&[("_trieonly", 0x20)]);
        let export = (LINKEDIT_AT + 0x200, trie.len());
        let builder = MachOBuilder::standard()
            .dyld_info(LC_DYLD_INFO_ONLY, [(0, 0), (0, 0), (0, 0), (0, 0), export])
            .bytes(LINKEDIT_AT + 0x200, &trie);
        if !with_symtab {
            return builder.build();
        }
        builder
            .symtab(LINKEDIT_AT, 3, LINKEDIT_AT + 0x100, strings.len())
            .bytes(LINKEDIT_AT, &table)
            .bytes(LINKEDIT_AT + 0x100, &strings)
            .build()
    }

    #[test]
    fn export_prefers_the_symbol_table_then_the_trie() {
        let image = open(&symbol_image(true));
        assert_eq!(image.symbols().len(), 3);
        assert_eq!(image.export("_alpha", LOAD).ok(), Some(LOAD + 0x800));
        assert_eq!(image.export("_TRIEONLY", LOAD).ok(), Some(LOAD + 0x20));
        assert!(matches!(
            image.export("_missing", LOAD),
            Err(MachoError::SymbolNotFound { .. })
        ));
        let low = image.export("_low", LOAD).unwrap_err();
        assert!(low.to_string().contains("precedes image base"));
        assert!(matches!(
            image.export("_Alpha", u64::MAX),
            Err(MachoError::Overflow { .. })
        ));
    }

    #[test]
    fn export_requires_a_symbol_table() {
        let image = open(&symbol_image(false));
        assert!(matches!(
            image.export("_trieonly", LOAD),
            Err(MachoError::SymbolNotFound { .. })
        ));
    }

    fn dyld_info_image(command: u32) -> Vec<u8> {
        let rebase = [0x11, 0x22, 0x20, 0x51, 0x00];
        let bind = [0x40, b'_', b'b', 0, 0x72, 0x28, 0x90, 0x00];
        let weak = [0x40, b'_', b'w', 0, 0x72, 0x30, 0x90, 0x00];
        let lazy = [
            0x72, 0x38, 0x40, b'_', b'l', 0, 0x90, 0x00, 0x72, 0x40, 0x40, b'_', b'm', 0, 0x90,
            0x00,
        ];
        let streams = [
            (LINKEDIT_AT, rebase.len()),
            (LINKEDIT_AT + 0x10, bind.len()),
            (LINKEDIT_AT + 0x20, weak.len()),
            (LINKEDIT_AT + 0x30, lazy.len()),
            (LINKEDIT_AT + 0x50, 1),
        ];
        MachOBuilder::standard()
            .dyld_info(command, streams)
            .bytes(LINKEDIT_AT, &rebase)
            .bytes(LINKEDIT_AT + 0x10, &bind)
            .bytes(LINKEDIT_AT + 0x20, &weak)
            .bytes(LINKEDIT_AT + 0x30, &lazy)
            .bytes(LINKEDIT_AT + 0x50, &[0xff])
            .pointer(DATA_AT + 0x20, BASE + 0x100)
            .build()
    }

    #[test]
    fn dyld_info_streams_decode_in_rebase_bind_weak_lazy_order() {
        let mut image = open(&dyld_info_image(LC_DYLD_INFO));
        let bind = |offset: u64, symbol: &str| Relocation::Bind {
            offset,
            symbol: symbol.to_owned(),
            addend: 0,
        };
        let expected = [
            Relocation::Rebase {
                offset: 0x1020,
                target: 0x100,
            },
            bind(0x1028, "_b"),
            bind(0x1030, "_w"),
            bind(0x1038, "_l"),
            bind(0x1040, "_m"),
        ];
        assert_eq!(image.relocations(), expected);
        let addresses: HashMap<&str, u64> =
            HashMap::from([("_b", 0xb0), ("_w", 0xc0), ("_l", 0xd0), ("_m", 0xe0)]);
        image
            .relocate(LOAD, |symbol: &str| {
                addresses.get(symbol).copied().ok_or("unknown")
            })
            .unwrap();
        let written: Vec<u64> = (0..5)
            .map(|index| pointer(&image, DATA_AT + 0x20 + index * 8))
            .collect();
        assert_eq!(written, [LOAD + 0x100, 0xb0, 0xc0, 0xd0, 0xe0]);
    }

    fn prelinked_image() -> Vec<u8> {
        MachOBuilder::standard()
            .segment("__ODD", BASE + 0x3006, 0x20, 0x2c00, 0x20)
            .segment("__TINY", BASE + 0x3100, 4, 0x2d00, 4)
            .pointer(0x900, 0x7777)
            .pointer(DATA_AT + 0x8, 0x7777)
            .pointer(DATA_AT + 0x10, 0x8888)
            .pointer(LINKEDIT_AT + 0x8, 0x7777)
            .pointer(0x2c02, 0x7777)
            .build()
    }

    #[test]
    fn prepare_prelinked_patches_data_pointers_in_place() {
        let mut image = open(&prelinked_image());
        let external = HashMap::from([(0x7777, "_ext".to_owned()), (0x8888, "_other".to_owned())]);
        let mut requested = Vec::new();
        image
            .prepare_prelinked(&external, |symbol: &str| {
                requested.push(symbol.to_owned());
                Ok::<u64, Infallible>(if symbol == "_ext" { 0xe000 } else { 0xf000 })
            })
            .unwrap();
        assert_eq!(requested, ["_ext", "_other"]);
        assert_eq!(image.loaded_base(), Some(BASE));
        assert_eq!(pointer(&image, DATA_AT + 0x8), 0xe000);
        assert_eq!(pointer(&image, DATA_AT + 0x10), 0xf000);
        assert_eq!(pointer(&image, 0x2c02), 0xe000);
        assert_eq!(pointer(&image, 0x900), 0x7777);
        assert_eq!(pointer(&image, LINKEDIT_AT + 0x8), 0x7777);
    }

    #[test]
    fn prepare_prelinked_without_imports_only_marks_the_image_loaded() {
        let input = prelinked_image();
        let mut image = open(&input);
        image.prepare_prelinked(&HashMap::new(), found).unwrap();
        assert_eq!(image.loaded_base(), Some(BASE));
        assert_eq!(pointer(&image, DATA_AT + 0x8), 0x7777);
        let mut failing = open(&input);
        let external = HashMap::from([(0x7777, "_ext".to_owned())]);
        let error = failing.prepare_prelinked(&external, missing).unwrap_err();
        assert!(matches!(error, MachoError::Resolve { .. }));
        assert_eq!(failing.loaded_base(), None);
    }

    const KERNEL_LOAD: u64 = 0x4000_0000;
    const KEXT: u64 = 0xabc;

    fn kernel_image() -> Vec<u8> {
        let (table, strings) = symbol_table(&[
            ("_kext", 0x01, BASE + 0x100_0000),
            ("_inside", 0x0f, BASE + 0x40),
            ("_null", 0x01, 0),
        ]);
        MachOBuilder::new(0x4000)
            .segment("__TEXT", BASE, 0x1000, 0, 0x1000)
            .segment("__TEXT_EXEC", BASE + 0x1000, 0x1000, 0x1000, 0x1000)
            .segment("__DATA", BASE + 0x2000, 0x1000, 0x2000, 0x1000)
            .segment("__LINKEDIT", BASE + 0x3000, 0x1000, 0x3000, 0x1000)
            .symtab(0x3000, 3, 0x3100, strings.len())
            .bytes(0x3000, &table)
            .bytes(0x3100, &strings)
            .pointer(0x1100, 0x40)
            .pointer(0x2000, 0x40)
            .pointer(0x2010, 0x100_0000)
            .pointer(0x2020, 0x200_0000)
            .pointer(0x2030, (1 << 30) | 0x40)
            .build()
    }

    fn resolve_kext(symbol: &str) -> Result<u64, String> {
        (symbol == "_kext")
            .then_some(KEXT)
            .ok_or_else(|| format!("unexpected {symbol}"))
    }

    #[test]
    fn kernel_cache_pointers_are_rebased_or_resolved() {
        let mut image = open(&kernel_image());
        image
            .relocate_kernel_cache_pointers(KERNEL_LOAD, BASE, resolve_kext)
            .unwrap();
        assert_eq!(pointer(&image, 0x2000), KERNEL_LOAD + 0x40);
        assert_eq!(pointer(&image, 0x2010), KEXT);
        assert_eq!(pointer(&image, 0x2020), 0x200_0000);
        assert_eq!(pointer(&image, 0x2030), (1 << 30) | 0x40);
        assert_eq!(pointer(&image, 0x1100), 0x40);
    }

    #[test]
    fn kernel_cache_pointer_failures() {
        let input = kernel_image();
        let mut image = open(&input);
        let overflow = image.relocate_kernel_cache_pointers(u64::MAX, BASE, resolve_kext);
        assert!(matches!(overflow, Err(MachoError::Overflow { .. })));
        let mut image = open(&input);
        image
            .relocate_kernel_cache_pointers(KERNEL_LOAD, u64::MAX, resolve_kext)
            .unwrap();
        assert_eq!(image.data(), open(&input).data());
        let mut image = open(&input);
        let error = image.relocate_kernel_cache_pointers(KERNEL_LOAD, BASE, missing);
        assert!(matches!(error, Err(MachoError::Resolve { .. })));
    }

    fn relocated(builder: MachOBuilder, load_base: u64) -> MachImage {
        let mut image = open(&builder.build());
        image.relocate(load_base, found).unwrap();
        image
    }

    fn text_only() -> MachOBuilder {
        MachOBuilder::new(0x1000).segment("__TEXT", BASE, 0x1000, 0, 0x1000)
    }

    #[test]
    fn load_plan_merges_regions_and_skips_unbacked_segments() {
        let builder = text_only()
            .segment("__BSS", BASE + 0x800, 0x1000, 0, 0)
            .segment("__EMPTY", BASE + 0x8000, 0, 0, 0)
            .segment("__FAR", BASE + 0x10008, 0x10, 0x100, 0x10);
        let image = relocated(builder, LOAD);
        let plan = image.load_plan().unwrap();
        assert_eq!(
            plan.regions,
            [
                MemoryRegion {
                    address: LOAD,
                    size: 0x2000
                },
                MemoryRegion {
                    address: LOAD + 0x10000,
                    size: 0x1000
                }
            ]
        );
        let placed: Vec<(&str, u64)> = plan.segments.iter().map(|s| (s.name, s.address)).collect();
        assert_eq!(placed, [("__TEXT", LOAD), ("__FAR", LOAD + 0x10008)]);
    }

    #[test]
    fn load_plan_requires_relocation() {
        let image = open(&text_only().build());
        let error = image.load_plan().unwrap_err();
        assert!(error.to_string().contains("must be relocated"));
    }

    #[test]
    fn load_plan_rejects_inconsistent_layouts() {
        let low = relocated(
            text_only().segment("__LOW", BASE - 0x1000, 0x1000, 0, 0),
            LOAD,
        );
        let error = low.load_plan().unwrap_err().to_string();
        assert!(error.contains("segment __LOW precedes image base"));
        let reordered = MachOBuilder::new(0x2000)
            .segment("__DATA", BASE + 0x1000, 0x1000, 0x1000, 0x1000)
            .segment("__TEXT", BASE, 0x1000, 0, 0x1000);
        let error = relocated(reordered, u64::MAX - 0x800)
            .load_plan()
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("address overflow: segment __DATA")
        );
        let error = relocated(text_only(), u64::MAX - 0x10)
            .load_plan()
            .unwrap_err();
        assert!(error.to_string().contains("segment __TEXT range"));
        let pagezero = MachOBuilder::new(0x100).segment("__PAGEZERO", 0, BASE, 0, 0);
        let error = relocated(pagezero, 0).load_plan().unwrap_err();
        assert!(error.to_string().contains("no loadable segments"));
        let big = text_only().segment("__BIG", BASE + 0x1000, 0x8000_0000, 0, 0);
        let error = relocated(big, LOAD).load_plan().unwrap_err();
        assert!(error.to_string().contains("too large"));
        let mut truncated = relocated(MachOBuilder::standard(), LOAD);
        truncated.data.truncate(DATA_AT + 0x800);
        let error = truncated.load_plan().unwrap_err();
        assert!(
            error
                .to_string()
                .contains("segment __DATA data exceeds image")
        );
    }

    #[test]
    fn open_rejects_inconsistent_segments() {
        let oversized = MachOBuilder::new(0x1000).segment("__TEXT", BASE, 0x10, 0, 0x20);
        let error = open_error(&oversized.build()).to_string();
        assert!(error.contains("exceeds its memory size"));
        let wrapping = MachOBuilder::new(0x1000).segment("__TEXT", u64::MAX - 1, 0x10, 0, 0);
        assert!(matches!(
            open_error(&wrapping.build()),
            MachoError::Overflow { .. }
        ));
        let beyond = MachOBuilder::new(0x1800).segment("__DATA", BASE, 0x1000, 0x1000, 0x1000);
        let error = open_error(&beyond.build()).to_string();
        assert!(error.contains("segment __DATA data exceeds image"));
    }

    #[test]
    fn open_rejects_linkedit_outside_the_image() {
        let section = MachOBuilder::new(0x1000)
            .segment("__TEXT", BASE, 0x1000, 0, 0x1000)
            .section("__text", BASE, 0x200, 0xf00, PURE_INSTRUCTIONS);
        let error = open_error(&section.build()).to_string();
        assert!(error.contains("instruction section __text exceeds image"));
        let chained = MachOBuilder::standard().chained_fixups(0x2f00, 0x200);
        let error = open_error(&chained.build()).to_string();
        assert!(error.contains("linkedit data exceeds image"));
        let rebase = MachOBuilder::standard().dyld_info(
            LC_DYLD_INFO,
            [(0x2f00, 0x200), (0, 0), (0, 0), (0, 0), (0, 0)],
        );
        let error = open_error(&rebase.build()).to_string();
        assert!(error.contains("linkedit data exceeds image"));
        let symtab = MachOBuilder::standard().symtab(0x2f00, 100, LINKEDIT_AT, 1);
        let error = open_error(&symtab.build()).to_string();
        assert!(error.contains("symbol table exceeds image"));
        let truncated = MachOBuilder::standard().chained_fixups(LINKEDIT_AT, 8);
        let error = open_error(&truncated.build()).to_string();
        assert!(error.contains("truncated chained fixups"));
    }

    #[test]
    fn unreadable_export_tries_yield_no_exports() {
        let range = |export| [(0, 0), (0, 0), (0, 0), (0, 0), export];
        let (table, strings) = symbol_table(&[("_x", 0x0f, BASE)]);
        for export in [(LINKEDIT_AT, 0), (0x2fff, 0x10), (LINKEDIT_AT + 0x100, 1)] {
            let image = open(
                &MachOBuilder::standard()
                    .dyld_info(LC_DYLD_INFO_ONLY, range(export))
                    .symtab(LINKEDIT_AT, 1, LINKEDIT_AT + 0x80, strings.len())
                    .bytes(LINKEDIT_AT, &table)
                    .bytes(LINKEDIT_AT + 0x80, &strings)
                    .bytes(LINKEDIT_AT + 0x100, &[0xff])
                    .build(),
            );
            assert_eq!(image.trie_exports, []);
            assert_eq!(image.export("_x", LOAD).ok(), Some(LOAD));
        }
    }
}
