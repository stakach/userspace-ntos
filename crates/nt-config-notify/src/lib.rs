//! # `nt-config-notify` — registry change notification
//!
//! The Configuration Manager's notify bookkeeping (NT `ntos/config/cmnotify.c`), without any
//! knowledge of how a request completes. A *notify block* belongs to one key body (one open of
//! a key) and fixes the filter and scope of that open's notify session on its first request.
//! Each `NtNotifyChangeKey` call posts one request on the block. A committed change that the
//! block's filter and scope cover completes every posted request with
//! `STATUS_NOTIFY_ENUM_DIR`; with none posted the block remembers the change and the next
//! request completes at once. Closing the key body, deleting its key or unloading its hive
//! completes the posted requests with `STATUS_NOTIFY_CLEANUP` and ends the session.
//!
//! The request payload `R` is the caller's: its completion surfaces (IO_STATUS_BLOCK, Event,
//! APC, waiting thread). This crate only decides which requests complete and with what status.

#![no_std]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

pub const REG_NOTIFY_CHANGE_NAME: u32 = 0x1;
pub const REG_NOTIFY_CHANGE_ATTRIBUTES: u32 = 0x2;
pub const REG_NOTIFY_CHANGE_LAST_SET: u32 = 0x4;
pub const REG_NOTIFY_CHANGE_SECURITY: u32 = 0x8;
pub const REG_LEGAL_CHANGE_FILTER: u32 = REG_NOTIFY_CHANGE_NAME
    | REG_NOTIFY_CHANGE_ATTRIBUTES
    | REG_NOTIFY_CHANGE_LAST_SET
    | REG_NOTIFY_CHANGE_SECURITY;

pub const STATUS_NOTIFY_CLEANUP: u32 = 0x0000_010B;
pub const STATUS_NOTIFY_ENUM_DIR: u32 = 0x0000_010C;

/// One open of a key: the owner of a notify session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyBody {
    pub process: u64,
    pub handle: u64,
}

/// A posted request, named so a waiter whose wait was aborted can withdraw it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PostId(u64);

impl PostId {
    pub const fn raw(self) -> u64 {
        self.0
    }
}

/// A request that is finished: deliver `status` through `request`'s completion surfaces.
#[derive(Debug, PartialEq, Eq)]
pub struct Completion<R> {
    pub post: PostId,
    pub body: KeyBody,
    pub thread: u64,
    pub status: u32,
    pub request: R,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Armed<R> {
    /// Posted; it completes on a later change or cleanup.
    Pending(PostId),
    /// The block remembered a change: the request is already complete.
    Posted(Completion<R>),
}

#[derive(Debug, PartialEq, Eq)]
pub enum ArmError<R> {
    /// A bit outside `REG_LEGAL_CHANGE_FILTER` (`STATUS_INVALID_PARAMETER`).
    InvalidFilter(R),
    /// No memory for the block or the request (`STATUS_INSUFFICIENT_RESOURCES`).
    InsufficientResources(R),
}

pub struct ChangeNotifier<R> {
    blocks: Vec<Block<R>>,
    next_post: u64,
}

struct Block<R> {
    body: KeyBody,
    /// Canonical key name: lower-case components, each preceded by `\`.
    key: String,
    filter: u32,
    watch_tree: bool,
    /// A covered change arrived while no request was posted.
    pending: bool,
    posts: Vec<Post<R>>,
}

struct Post<R> {
    id: PostId,
    thread: u64,
    request: R,
}

impl<R> Default for ChangeNotifier<R> {
    fn default() -> Self {
        Self::new()
    }
}

impl<R> ChangeNotifier<R> {
    pub const fn new() -> Self {
        Self {
            blocks: Vec::new(),
            next_post: 1,
        }
    }

    /// No notify session exists: no change can complete or be remembered by anything.
    pub fn is_idle(&self) -> bool {
        self.blocks.is_empty()
    }

    /// Requests posted and not yet completed.
    pub fn posted_requests(&self) -> usize {
        self.blocks.iter().map(|block| block.posts.len()).sum()
    }

    /// Post one request on `body`'s notify block, creating the block on the body's first
    /// request. A later request's `filter` and `watch_tree` are ignored: the session keeps the
    /// first request's (`CmpNotifyChangeKey`).
    pub fn arm(
        &mut self,
        body: KeyBody,
        key: &str,
        filter: u32,
        watch_tree: bool,
        thread: u64,
        request: R,
    ) -> Result<Armed<R>, ArmError<R>> {
        if filter & !REG_LEGAL_CHANGE_FILTER != 0 {
            return Err(ArmError::InvalidFilter(request));
        }
        let Some(id) = self.next_post.checked_add(1).map(|next| {
            let id = PostId(self.next_post);
            self.next_post = next;
            id
        }) else {
            return Err(ArmError::InsufficientResources(request));
        };
        let index = match self.blocks.iter().position(|block| block.body == body) {
            Some(index) => index,
            None => {
                let Some(key) = canonical(key) else {
                    return Err(ArmError::InsufficientResources(request));
                };
                if self.blocks.try_reserve(1).is_err() {
                    return Err(ArmError::InsufficientResources(request));
                }
                self.blocks.push(Block {
                    body,
                    key,
                    filter,
                    watch_tree,
                    pending: false,
                    posts: Vec::new(),
                });
                self.blocks.len() - 1
            }
        };
        let block = &mut self.blocks[index];
        if block.pending {
            block.pending = false;
            return Ok(Armed::Posted(Completion {
                post: id,
                body,
                thread,
                status: STATUS_NOTIFY_ENUM_DIR,
                request,
            }));
        }
        if block.posts.try_reserve(1).is_err() {
            if block.posts.is_empty() && !block.pending {
                // A block created for this request has no session to keep.
                self.blocks.swap_remove(index);
            }
            return Err(ArmError::InsufficientResources(request));
        }
        block.posts.push(Post {
            id,
            thread,
            request,
        });
        Ok(Armed::Pending(id))
    }

    /// A change of kind `filter` at `key` itself: a value set or deleted
    /// (`REG_NOTIFY_CHANGE_LAST_SET`), or its security changed
    /// (`REG_NOTIFY_CHANGE_ATTRIBUTES | REG_NOTIFY_CHANGE_SECURITY`).
    pub fn report_key_changed(&mut self, key: &str, filter: u32) -> Vec<Completion<R>> {
        let mut completions = Vec::new();
        if let Some(key) = canonical(key) {
            self.report(&key, filter, &mut completions);
        }
        completions
    }

    /// `subkey` was created or deleted. NT reports that as a name change of its parent.
    pub fn report_subkey_changed(&mut self, subkey: &str) -> Vec<Completion<R>> {
        let mut completions = Vec::new();
        if let Some(subkey) = canonical(subkey) {
            self.report(parent(&subkey), REG_NOTIFY_CHANGE_NAME, &mut completions);
        }
        completions
    }

    /// `key` was deleted: its parent sees a name change, and every notify session on the key
    /// itself ends with `STATUS_NOTIFY_CLEANUP`.
    pub fn key_deleted(&mut self, key: &str) -> Vec<Completion<R>> {
        let mut completions = Vec::new();
        if let Some(key) = canonical(key) {
            self.report(parent(&key), REG_NOTIFY_CHANGE_NAME, &mut completions);
            self.flush(|block| block.key == key, &mut completions);
        }
        completions
    }

    /// The hive mounted at `root` was unloaded: watchers that cover the root see it change,
    /// then every session at or below it ends with `STATUS_NOTIFY_CLEANUP`.
    pub fn subtree_removed(&mut self, root: &str) -> Vec<Completion<R>> {
        let mut completions = Vec::new();
        if let Some(root) = canonical(root) {
            self.report(parent(&root), REG_NOTIFY_CHANGE_NAME, &mut completions);
            self.flush(|block| covers(&root, &block.key), &mut completions);
        }
        completions
    }

    /// The handle was closed: its session ends with `STATUS_NOTIFY_CLEANUP`.
    pub fn close_key_body(&mut self, body: KeyBody) -> Vec<Completion<R>> {
        let mut completions = Vec::new();
        self.flush(|block| block.body == body, &mut completions);
        completions
    }

    /// Every key body of `process` was closed.
    pub fn close_process(&mut self, process: u64) -> Vec<Completion<R>> {
        let mut completions = Vec::new();
        self.flush(|block| block.body.process == process, &mut completions);
        completions
    }

    /// `thread` of `process` exited: its posted requests end with `STATUS_NOTIFY_CLEANUP`
    /// (`CmNotifyRunDown`). The sessions stay with their key bodies.
    pub fn thread_exited(&mut self, process: u64, thread: u64) -> Vec<Completion<R>> {
        let mut completions = Vec::new();
        for block in &mut self.blocks {
            if block.body.process != process {
                continue;
            }
            let mut index = 0;
            while index < block.posts.len() {
                if block.posts[index].thread == thread {
                    let post = block.posts.remove(index);
                    completions.push(complete(block.body, post, STATUS_NOTIFY_CLEANUP));
                } else {
                    index += 1;
                }
            }
        }
        completions
    }

    /// Remove one posted request without completing it: its synchronous wait was aborted.
    pub fn withdraw(&mut self, post: PostId) -> Option<R> {
        for block in &mut self.blocks {
            if let Some(index) = block.posts.iter().position(|posted| posted.id == post) {
                return Some(block.posts.remove(index).request);
            }
        }
        None
    }

    /// `CmpReportNotifyHelper`: a block is relevant when its key is `key` or, for a tree
    /// watch, an ancestor of it, and its filter shares a bit with the change.
    fn report(&mut self, key: &str, filter: u32, completions: &mut Vec<Completion<R>>) {
        for block in &mut self.blocks {
            if block.filter & filter == 0 {
                continue;
            }
            if !(block.key == key || (block.watch_tree && covers(&block.key, key))) {
                continue;
            }
            if block.posts.is_empty() {
                block.pending = true;
                continue;
            }
            block.pending = false;
            let body = block.body;
            completions.extend(
                block
                    .posts
                    .drain(..)
                    .map(|post| complete(body, post, STATUS_NOTIFY_ENUM_DIR)),
            );
        }
    }

    /// `CmpFlushNotify`: end the selected sessions.
    fn flush(
        &mut self,
        mut selected: impl FnMut(&Block<R>) -> bool,
        completions: &mut Vec<Completion<R>>,
    ) {
        let mut index = 0;
        while index < self.blocks.len() {
            if selected(&self.blocks[index]) {
                let block = self.blocks.remove(index);
                let body = block.body;
                completions.extend(
                    block
                        .posts
                        .into_iter()
                        .map(|post| complete(body, post, STATUS_NOTIFY_CLEANUP)),
                );
            } else {
                index += 1;
            }
        }
    }
}

fn complete<R>(body: KeyBody, post: Post<R>, status: u32) -> Completion<R> {
    Completion {
        post: post.id,
        body,
        thread: post.thread,
        status,
        request: post.request,
    }
}

/// Lower-case components, each preceded by `\`; the namespace root is the empty string.
/// `None` when the name cannot be stored.
fn canonical(key: &str) -> Option<String> {
    let mut out = String::new();
    out.try_reserve(key.len() + 1).ok()?;
    for component in key.split('\\').filter(|component| !component.is_empty()) {
        out.push('\\');
        for character in component.chars() {
            out.extend(character.to_lowercase());
        }
    }
    Some(out)
}

/// The canonical name of `key`'s parent.
fn parent(key: &str) -> &str {
    key.rfind('\\').map_or("", |separator| &key[..separator])
}

/// Whether canonical `key` is `ancestor` or lies below it.
fn covers(ancestor: &str, key: &str) -> bool {
    key.strip_prefix(ancestor)
        .is_some_and(|rest| rest.is_empty() || rest.starts_with('\\'))
}
