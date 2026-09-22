//! Logical-client association for provider jobs, independently of callback capability.

use alloc::vec::Vec;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DispatchClientIdentity {
    pub dispatch: u64,
    pub process_slot: u32,
    pub thread: u64,
    pub badge: u64,
}

pub struct ProviderDispatchClients<T> {
    entries: Vec<(DispatchClientIdentity, T)>,
}

impl<T: Copy> ProviderDispatchClients<T> {
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Inputs are authenticated root metadata, not provider claims. A dispatch cannot acquire a
    /// different logical client; exact re-registration refreshes only its associated snapshot.
    pub fn register(&mut self, identity: DispatchClientIdentity, client: T) -> bool {
        if identity.dispatch == 0 || identity.thread == 0 || identity.badge == 0 {
            return false;
        }
        if let Some((held, payload)) = self
            .entries
            .iter_mut()
            .find(|(held, _)| held.dispatch == identity.dispatch)
        {
            if *held != identity {
                return false;
            }
            *payload = client;
            return true;
        }
        if self.entries.try_reserve(1).is_err() {
            return false;
        }
        self.entries.push((identity, client));
        true
    }

    pub fn resolve(&self, identity: DispatchClientIdentity) -> Option<T> {
        self.entries
            .iter()
            .find(|(held, _)| *held == identity)
            .map(|(_, payload)| *payload)
    }

    pub fn dispatch(&self, dispatch: u64) -> Option<T> {
        self.entries
            .iter()
            .find(|(held, _)| held.dispatch == dispatch)
            .map(|(_, payload)| *payload)
    }

    pub fn retire(&mut self, identity: DispatchClientIdentity) -> bool {
        let Some(index) = self.entries.iter().position(|(held, _)| *held == identity) else {
            return false;
        };
        self.entries.swap_remove(index);
        true
    }

    pub fn retain(&mut self, mut keep: impl FnMut(T) -> bool) {
        self.entries.retain(|(_, payload)| keep(*payload));
    }
    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

impl<T: Copy> Default for ProviderDispatchClients<T> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct Client {
        pid: u64,
        callback_capable: bool,
    }
    fn identity(dispatch: u64) -> DispatchClientIdentity {
        DispatchClientIdentity {
            dispatch,
            process_slot: 3,
            thread: 9,
            badge: 4,
        }
    }

    #[test]
    fn non_callback_job_has_exact_client_until_terminal_retirement() {
        let mut clients = ProviderDispatchClients::new();
        let client = Client {
            pid: 42,
            callback_capable: false,
        };
        assert!(clients.register(identity(1), client));
        assert_eq!(clients.resolve(identity(1)), Some(client));
        assert_eq!(clients.dispatch(1), Some(client));
        assert!(!clients.retire(identity(2)));
        assert_eq!(clients.resolve(identity(1)), Some(client));
        assert!(clients.retire(identity(1)));
        assert_eq!(clients.dispatch(1), None);
    }

    #[test]
    fn nested_callback_does_not_replace_outer_non_callback_association() {
        let mut clients = ProviderDispatchClients::new();
        let outer = Client {
            pid: 42,
            callback_capable: false,
        };
        let inner = Client {
            pid: 43,
            callback_capable: true,
        };
        assert!(clients.register(identity(1), outer));
        assert!(clients.register(identity(2), inner));
        assert!(clients.retire(identity(2)));
        assert_eq!(clients.dispatch(1), Some(outer));
        assert!(clients.retire(identity(1)));
    }

    #[test]
    fn mismatched_client_cannot_replace_or_retire_a_dispatch() {
        let mut clients = ProviderDispatchClients::new();
        let client = Client {
            pid: 42,
            callback_capable: false,
        };
        assert!(clients.register(identity(1), client));
        let mut foreign = identity(1);
        foreign.thread += 1;
        assert!(!clients.register(foreign, client));
        assert!(!clients.retire(foreign));
        assert_eq!(clients.resolve(foreign), None);
        assert!(clients.retire(identity(1)));
    }
}
