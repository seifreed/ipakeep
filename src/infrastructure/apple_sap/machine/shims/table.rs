//! Symbol table of the service area: one `ret` slot per emulated function and
//! 8-byte aligned cells for emulated data symbols.

use std::collections::HashMap;
use std::rc::Rc;

use crate::infrastructure::apple_sap::emu::Engine;

use super::call::ShimCall;
use super::error::ShimError;
use super::layout::{SHIM_AREA_SIZE, SHIM_BASE, SHIM_CODE_SIZE, SHIM_SLOT_SIZE, align};

/// Host implementation of one guest function.
pub(super) type Handler = fn(&mut ShimCall<'_, '_>) -> Result<(), ShimError>;

/// Alignment and minimum footprint of a data symbol.
const DATA_ALIGNMENT: u64 = 8;

/// A registered shim: its symbol name and host implementation.
#[derive(Clone)]
pub(super) struct Entry {
    pub(super) name: Rc<str>,
    pub(super) handler: Handler,
}

/// Maps symbol names to service-area addresses and code slots to handlers.
pub(super) struct ShimTable {
    entries: HashMap<u64, Entry>,
    symbols: HashMap<String, u64>,
    code_cursor: u64,
    data_cursor: u64,
}

impl Default for ShimTable {
    fn default() -> Self {
        Self {
            entries: HashMap::new(),
            symbols: HashMap::new(),
            code_cursor: SHIM_BASE,
            data_cursor: SHIM_BASE + SHIM_CODE_SIZE,
        }
    }
}

impl ShimTable {
    /// Binds `name` to a fresh code slot running `handler`; an existing symbol
    /// keeps its first binding.
    pub(super) fn add_function(&mut self, name: &str, handler: Handler) -> Result<u64, ShimError> {
        if let Some(&address) = self.symbols.get(name) {
            return Ok(address);
        }
        if self.code_cursor + SHIM_SLOT_SIZE > SHIM_BASE + SHIM_CODE_SIZE {
            return Err(ShimError::CodeAreaFull);
        }
        let address = self.code_cursor;
        self.code_cursor += SHIM_SLOT_SIZE;
        self.entries.insert(
            address,
            Entry {
                name: Rc::from(name),
                handler,
            },
        );
        self.symbols.insert(name.to_owned(), address);

        Ok(address)
    }

    /// Binds `name` to an 8-byte aligned data cell initialised with `data`.
    pub(super) fn add_data(
        &mut self,
        engine: &mut Engine<'_>,
        name: &str,
        data: &[u8],
    ) -> Result<u64, ShimError> {
        if let Some(&address) = self.symbols.get(name) {
            return Ok(address);
        }
        let address = align(self.data_cursor, DATA_ALIGNMENT).ok_or(ShimError::DataAreaFull)?;
        let length = data.len() as u64;
        if address + length > SHIM_BASE + SHIM_AREA_SIZE {
            return Err(ShimError::DataAreaFull);
        }
        engine.mem_write(address, data)?;
        self.data_cursor = address + length.max(DATA_ALIGNMENT);
        self.symbols.insert(name.to_owned(), address);

        Ok(address)
    }

    /// Returns the address of `name`, binding unknown imports to a slot that
    /// fails with [`ShimError::UnsupportedImport`] when called.
    pub(super) fn resolve(&mut self, name: &str) -> Result<u64, ShimError> {
        self.add_function(name, unsupported_import)
    }

    /// Returns the address bound to `name`, if any.
    pub(super) fn symbol(&self, name: &str) -> Option<u64> {
        self.symbols.get(name).copied()
    }

    /// Returns the shim whose slot starts at `address`.
    pub(super) fn entry(&self, address: u64) -> Option<Entry> {
        self.entries.get(&address).cloned()
    }
}

fn unsupported_import(call: &mut ShimCall<'_, '_>) -> Result<(), ShimError> {
    Err(ShimError::UnsupportedImport {
        name: call.name().to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOOP: Handler = |_| Ok(());

    #[test]
    fn functions_get_consecutive_slots_and_keep_first_binding() {
        let mut table = ShimTable::default();
        let first = table.add_function("_a", NOOP).expect("a");
        let second = table.add_function("_b", NOOP).expect("b");
        assert_eq!(first, SHIM_BASE);
        assert_eq!(second, SHIM_BASE + SHIM_SLOT_SIZE);
        assert_eq!(
            table.add_function("_a", unsupported_import).ok(),
            Some(first)
        );
        assert_eq!(table.resolve("_b").ok(), Some(second));
        assert_eq!(table.symbol("_a"), Some(first));
        assert_eq!(table.entry(first).map(|e| e.name), Some(Rc::from("_a")));
        assert!(table.entry(first + 4).is_none());
    }

    #[test]
    fn code_area_reports_exhaustion() {
        let mut table = ShimTable::default();
        let slots = SHIM_CODE_SIZE / SHIM_SLOT_SIZE;
        for index in 0..slots {
            table.resolve(&format!("_f{index}")).expect("slot");
        }
        assert!(matches!(
            table.resolve("_overflow"),
            Err(ShimError::CodeAreaFull)
        ));
    }
}
