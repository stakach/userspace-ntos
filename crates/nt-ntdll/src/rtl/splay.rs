//! `RTL_SPLAY_LINKS` helpers and splay-tree routines.
//!
//! This is the pure userspace RTL tree logic behind exports such as `RtlSplay`,
//! `RtlDelete`, `RtlRealSuccessor`, and the splay-backed generic table. It uses the
//! byte-exact ReactOS/Windows `RTL_SPLAY_LINKS` layout.

use core::ptr::null_mut;

/// `RTL_SPLAY_LINKS` (`Parent`, `LeftChild`, `RightChild`).
#[repr(C)]
#[derive(Debug)]
pub struct SplayLinks {
    pub parent: *mut SplayLinks,
    pub left_child: *mut SplayLinks,
    pub right_child: *mut SplayLinks,
}

impl SplayLinks {
    /// A detached, uninitialized-by-RTL link record.
    pub const fn zeroed() -> Self {
        Self {
            parent: null_mut(),
            left_child: null_mut(),
            right_child: null_mut(),
        }
    }
}

/// Size of `RTL_SPLAY_LINKS` on x64.
pub const SPLAY_LINKS_SIZE: usize = 0x18;

/// Initialize an `RTL_SPLAY_LINKS` record as a root with no children.
///
/// # Safety
/// `links` is writable for a `SplayLinks`.
pub unsafe fn initialize_splay_links(links: *mut SplayLinks) {
    if links.is_null() {
        return;
    }
    unsafe {
        (*links).parent = links;
        (*links).left_child = null_mut();
        (*links).right_child = null_mut();
    }
}

/// Insert `child` as `parent`'s left child.
///
/// # Safety
/// `parent` and `child` are valid `SplayLinks`.
pub unsafe fn insert_as_left_child(parent: *mut SplayLinks, child: *mut SplayLinks) {
    unsafe {
        (*parent).left_child = child;
        (*child).parent = parent;
    }
}

/// Insert `child` as `parent`'s right child.
///
/// # Safety
/// `parent` and `child` are valid `SplayLinks`.
pub unsafe fn insert_as_right_child(parent: *mut SplayLinks, child: *mut SplayLinks) {
    unsafe {
        (*parent).right_child = child;
        (*child).parent = parent;
    }
}

#[inline]
unsafe fn is_root(links: *mut SplayLinks) -> bool {
    !links.is_null() && unsafe { (*links).parent == links }
}

#[inline]
unsafe fn is_left_child(links: *mut SplayLinks) -> bool {
    if links.is_null() {
        return false;
    }
    let parent = unsafe { (*links).parent };
    !parent.is_null() && parent != links && unsafe { (*parent).left_child == links }
}

#[inline]
unsafe fn is_right_child(links: *mut SplayLinks) -> bool {
    if links.is_null() {
        return false;
    }
    let parent = unsafe { (*links).parent };
    !parent.is_null() && parent != links && unsafe { (*parent).right_child == links }
}

unsafe fn replace_child(parent: *mut SplayLinks, old: *mut SplayLinks, new_child: *mut SplayLinks) {
    unsafe {
        if (*parent).left_child == old {
            (*parent).left_child = new_child;
        } else {
            (*parent).right_child = new_child;
        }
        if !new_child.is_null() {
            (*new_child).parent = parent;
        }
    }
}

unsafe fn rotate_left(x: *mut SplayLinks) {
    unsafe {
        let y = (*x).right_child;
        if y.is_null() {
            return;
        }
        (*x).right_child = (*y).left_child;
        if !(*x).right_child.is_null() {
            (*(*x).right_child).parent = x;
        }

        if is_root(x) {
            (*y).parent = y;
        } else {
            let p = (*x).parent;
            (*y).parent = p;
            replace_child(p, x, y);
        }

        (*y).left_child = x;
        (*x).parent = y;
    }
}

unsafe fn rotate_right(x: *mut SplayLinks) {
    unsafe {
        let y = (*x).left_child;
        if y.is_null() {
            return;
        }
        (*x).left_child = (*y).right_child;
        if !(*x).left_child.is_null() {
            (*(*x).left_child).parent = x;
        }

        if is_root(x) {
            (*y).parent = y;
        } else {
            let p = (*x).parent;
            (*y).parent = p;
            replace_child(p, x, y);
        }

        (*y).right_child = x;
        (*x).parent = y;
    }
}

/// `RtlSplay`.
///
/// # Safety
/// `links` belongs to a well-formed `RTL_SPLAY_LINKS` tree.
pub unsafe fn splay(links: *mut SplayLinks) -> *mut SplayLinks {
    if links.is_null() {
        return null_mut();
    }
    unsafe {
        while !is_root(links) {
            let parent = (*links).parent;
            if is_root(parent) {
                if (*parent).left_child == links {
                    rotate_right(parent);
                } else {
                    rotate_left(parent);
                }
            } else {
                let grand = (*parent).parent;
                let links_left = (*parent).left_child == links;
                let parent_left = (*grand).left_child == parent;
                match (links_left, parent_left) {
                    (true, true) => {
                        rotate_right(grand);
                        rotate_right(parent);
                    }
                    (false, false) => {
                        rotate_left(grand);
                        rotate_left(parent);
                    }
                    (true, false) => {
                        rotate_right(parent);
                        rotate_left(grand);
                    }
                    (false, true) => {
                        rotate_left(parent);
                        rotate_right(grand);
                    }
                }
            }
        }
        links
    }
}

/// `RtlSubtreePredecessor`.
///
/// # Safety
/// `links` is a valid node.
pub unsafe fn subtree_predecessor(links: *mut SplayLinks) -> *mut SplayLinks {
    if links.is_null() {
        return null_mut();
    }
    unsafe {
        let mut child = (*links).left_child;
        if child.is_null() {
            return null_mut();
        }
        while !(*child).right_child.is_null() {
            child = (*child).right_child;
        }
        child
    }
}

/// `RtlSubtreeSuccessor`.
///
/// # Safety
/// `links` is a valid node.
pub unsafe fn subtree_successor(links: *mut SplayLinks) -> *mut SplayLinks {
    if links.is_null() {
        return null_mut();
    }
    unsafe {
        let mut child = (*links).right_child;
        if child.is_null() {
            return null_mut();
        }
        while !(*child).left_child.is_null() {
            child = (*child).left_child;
        }
        child
    }
}

/// `RtlRealPredecessor`.
///
/// # Safety
/// `links` is a valid node.
pub unsafe fn real_predecessor(links: *mut SplayLinks) -> *mut SplayLinks {
    if links.is_null() {
        return null_mut();
    }
    unsafe {
        let subtree = subtree_predecessor(links);
        if !subtree.is_null() {
            return subtree;
        }
        let mut child = links;
        while is_left_child(child) {
            child = (*child).parent;
        }
        if is_right_child(child) {
            (*child).parent
        } else {
            null_mut()
        }
    }
}

/// `RtlRealSuccessor`.
///
/// # Safety
/// `links` is a valid node.
pub unsafe fn real_successor(links: *mut SplayLinks) -> *mut SplayLinks {
    if links.is_null() {
        return null_mut();
    }
    unsafe {
        let subtree = subtree_successor(links);
        if !subtree.is_null() {
            return subtree;
        }
        let mut child = links;
        while is_right_child(child) {
            child = (*child).parent;
        }
        if is_left_child(child) {
            (*child).parent
        } else {
            null_mut()
        }
    }
}

/// `RtlDelete`.
///
/// Removes `links` and returns the new root after splaying.
///
/// # Safety
/// `links` belongs to a well-formed tree.
pub unsafe fn delete(links: *mut SplayLinks) -> *mut SplayLinks {
    if links.is_null() {
        return null_mut();
    }
    unsafe {
        let root = splay(links);
        let left = (*root).left_child;
        let right = (*root).right_child;

        (*root).left_child = null_mut();
        (*root).right_child = null_mut();
        (*root).parent = root;

        if left.is_null() {
            if !right.is_null() {
                (*right).parent = right;
            }
            return right;
        }
        if right.is_null() {
            (*left).parent = left;
            return left;
        }

        (*left).parent = left;
        (*right).parent = right;
        let mut max_left = left;
        while !(*max_left).right_child.is_null() {
            max_left = (*max_left).right_child;
        }
        let new_root = splay(max_left);
        (*new_root).right_child = right;
        (*right).parent = new_root;
        new_root
    }
}

unsafe fn transplant(root: *mut *mut SplayLinks, old: *mut SplayLinks, new_node: *mut SplayLinks) {
    unsafe {
        if is_root(old) {
            *root = new_node;
            if !new_node.is_null() {
                (*new_node).parent = new_node;
            }
        } else {
            let parent = (*old).parent;
            replace_child(parent, old, new_node);
        }
    }
}

/// `RtlDeleteNoSplay`.
///
/// # Safety
/// `links` belongs to the tree rooted at `*root`.
pub unsafe fn delete_no_splay(links: *mut SplayLinks, root: *mut *mut SplayLinks) {
    if links.is_null() || root.is_null() {
        return;
    }
    unsafe {
        if (*links).left_child.is_null() {
            transplant(root, links, (*links).right_child);
        } else if (*links).right_child.is_null() {
            transplant(root, links, (*links).left_child);
        } else {
            let pred = subtree_predecessor(links);
            if (*pred).parent != links {
                transplant(root, pred, (*pred).left_child);
                (*pred).left_child = (*links).left_child;
                (*(*pred).left_child).parent = pred;
            }
            transplant(root, links, pred);
            (*pred).right_child = (*links).right_child;
            if !(*pred).right_child.is_null() {
                (*(*pred).right_child).parent = pred;
            }
        }
        (*links).parent = links;
        (*links).left_child = null_mut();
        (*links).right_child = null_mut();
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    unsafe fn node(nodes: &mut [SplayLinks], i: usize) -> *mut SplayLinks {
        nodes.as_mut_ptr().wrapping_add(i)
    }

    #[test]
    fn splay_rotates_node_to_root() {
        let mut nodes = [
            SplayLinks::zeroed(),
            SplayLinks::zeroed(),
            SplayLinks::zeroed(),
        ];
        unsafe {
            let root = node(&mut nodes, 1);
            let left = node(&mut nodes, 0);
            let right = node(&mut nodes, 2);
            initialize_splay_links(root);
            initialize_splay_links(left);
            initialize_splay_links(right);
            insert_as_left_child(root, left);
            insert_as_right_child(root, right);

            assert_eq!(splay(left), left);
            assert_eq!((*left).parent, left);
            assert_eq!((*left).right_child, root);
            assert_eq!((*root).parent, left);
            assert_eq!((*root).right_child, right);
            assert_eq!((*right).parent, root);
        }
    }

    #[test]
    fn successor_and_predecessor_walk_across_parents() {
        let mut nodes = [
            SplayLinks::zeroed(),
            SplayLinks::zeroed(),
            SplayLinks::zeroed(),
        ];
        unsafe {
            let root = node(&mut nodes, 1);
            let left = node(&mut nodes, 0);
            let right = node(&mut nodes, 2);
            initialize_splay_links(root);
            initialize_splay_links(left);
            initialize_splay_links(right);
            insert_as_left_child(root, left);
            insert_as_right_child(root, right);

            assert_eq!(real_successor(left), root);
            assert_eq!(real_predecessor(right), root);
            assert_eq!(subtree_predecessor(root), left);
            assert_eq!(subtree_successor(root), right);
        }
    }

    #[test]
    fn delete_removes_root_and_rejoins_subtrees() {
        let mut nodes = [
            SplayLinks::zeroed(),
            SplayLinks::zeroed(),
            SplayLinks::zeroed(),
        ];
        unsafe {
            let root = node(&mut nodes, 1);
            let left = node(&mut nodes, 0);
            let right = node(&mut nodes, 2);
            initialize_splay_links(root);
            initialize_splay_links(left);
            initialize_splay_links(right);
            insert_as_left_child(root, left);
            insert_as_right_child(root, right);

            let new_root = delete(root);
            assert!(!new_root.is_null());
            assert_eq!((*new_root).parent, new_root);
            assert_eq!(real_successor(left), right);
            assert_eq!(real_predecessor(right), left);
        }
    }

    #[test]
    fn delete_no_splay_updates_root_pointer() {
        let mut nodes = [SplayLinks::zeroed(), SplayLinks::zeroed()];
        unsafe {
            let mut root = node(&mut nodes, 0);
            let right = node(&mut nodes, 1);
            initialize_splay_links(root);
            initialize_splay_links(right);
            insert_as_right_child(root, right);

            delete_no_splay(root, &mut root);
            assert_eq!(root, right);
            assert_eq!((*right).parent, right);
        }
    }
}
