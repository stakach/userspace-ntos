//! One line per distinct access-check refusal, naming the object and the subject.
//! Instrumentation of decisions already made; never an authorization source.

use core::cell::RefCell;

use crate::{print_hex, print_str, print_u64, ExecNtHandler};
use nt_security::{AccessDenialKey, AccessDenialLedger, AccessDenialReport};

const MAX_REPORTED_DENIALS: usize = 96;

#[derive(Clone, Copy)]
pub(crate) enum DeniedObject {
    Port = 1,
    Directory = 2,
    Section = 3,
    Key = 4,
}

impl DeniedObject {
    fn label(self) -> &'static [u8] {
        match self {
            Self::Port => b"Port",
            Self::Directory => b"Directory",
            Self::Section => b"Section",
            Self::Key => b"Key",
        }
    }
}

pub(crate) struct AccessDenialTrace(RefCell<AccessDenialLedger>);

impl AccessDenialTrace {
    pub(crate) fn new() -> Self {
        Self(RefCell::new(AccessDenialLedger::new(MAX_REPORTED_DENIALS)))
    }
}

impl ExecNtHandler {
    /// Report a refused access by the current caller to the object named by UTF-16 `name`.
    pub(crate) fn trace_access_denied(&self, object: DeniedObject,
        name: impl Iterator<Item = u16> + Clone, desired: u32, granted: u32, status: u32) {
        let process = self.pm_pid_for_pi(self.pi);
        let thread = u32::try_from(self.current_tid).ok();
        let primary = process.and_then(|process| self.pm.process_primary_token(process));
        let client = thread.and_then(|thread| self.pm.thread_impersonation(thread))
            .map(|context| context.token);
        let effective = client.or(primary);
        let report = self.access_denials.0.borrow_mut().observe(AccessDenialKey {
            object_type: object as u32,
            name: AccessDenialKey::name_hash(name.clone()),
            desired_access: desired,
            process: process.unwrap_or(0),
            token: effective.map_or(0, |token| token.raw()),
        });
        if report == AccessDenialReport::Suppress {
            return;
        }
        print_str(b"[access-denied] type=");
        print_str(object.label());
        print_str(b" name=\"");
        for unit in name.take(160) {
            print_str(&[u8::try_from(unit).ok().filter(|byte| (0x20..0x7f).contains(byte))
                .unwrap_or(b'?')]);
        }
        print_str(b"\" desired=0x");
        print_hex(desired);
        print_str(b" granted=0x");
        print_hex(granted);
        print_str(b" status=0x");
        print_hex(status);
        print_str(b" pi=");
        print_u64(self.pi as u64);
        print_str(b" pid=");
        print_u64(u64::from(process.unwrap_or(0)));
        print_str(b" tid=");
        print_u64(self.current_tid);
        print_str(b" token=");
        print_u64(primary.map_or(0, |token| u64::from(token.raw())));
        print_str(b" client-token=");
        print_u64(client.map_or(0, |token| u64::from(token.raw())));
        if let Some(token) = effective.and_then(|token| self.token_store.get(token)) {
            print_str(b" user-rid=");
            print_u64(token.user.sub_authorities.last().copied().map_or(u64::MAX, u64::from));
            print_str(b" integrity=0x");
            match token.integrity_level {
                Some(level) => print_hex(level),
                None => print_str(b"none"),
            }
        }
        if report == AccessDenialReport::ReportFinal {
            print_str(b" (last reported denial)");
        }
        print_str(b"\n");
    }
}
