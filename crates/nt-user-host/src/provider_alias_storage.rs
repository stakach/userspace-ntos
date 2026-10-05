//! Fallible page-bounded metadata storage. Directory growth never relocates leaf elements.
use alloc::vec::Vec;
use core::ops::{Index, IndexMut};

const PAGE_BYTES: usize = 4096;

enum Node<T> {
    Empty,
    Leaf(Vec<T>),
    Branch(Vec<Node<T>>),
}

pub(super) struct PageSequence<T> {
    root: Node<T>,
    depth: usize,
    len: usize,
}

impl<T> PageSequence<T> {
    pub(super) const fn new() -> Self {
        Self {
            root: Node::Empty,
            depth: 0,
            len: 0,
        }
    }

    pub(super) const fn leaf_capacity() -> usize {
        let size = core::mem::size_of::<T>();
        if size == 0 {
            0
        } else {
            PAGE_BYTES / size
        }
    }

    const fn fanout() -> usize {
        PAGE_BYTES / core::mem::size_of::<Node<T>>()
    }

    fn capacity_at(depth: usize) -> usize {
        let mut capacity = Self::leaf_capacity();
        for _ in 0..depth {
            capacity = capacity.saturating_mul(Self::fanout());
        }
        capacity
    }

    pub(super) fn len(&self) -> usize {
        self.len
    }
    pub(super) fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn branch() -> Result<Vec<Node<T>>, ()> {
        let mut children = Vec::new();
        children.try_reserve_exact(Self::fanout()).map_err(|_| ())?;
        children.resize_with(Self::fanout(), || Node::Empty);
        Ok(children)
    }

    fn reserve_node(node: &mut Node<T>, depth: usize, index: usize) -> Result<(), ()> {
        if depth == 0 {
            if matches!(node, Node::Empty) {
                let mut values = Vec::new();
                values
                    .try_reserve_exact(Self::leaf_capacity())
                    .map_err(|_| ())?;
                *node = Node::Leaf(values);
            }
            return Ok(());
        }
        if matches!(node, Node::Empty) {
            *node = Node::Branch(Self::branch()?);
        }
        let Node::Branch(children) = node else {
            unreachable!("directory depth");
        };
        let span = Self::capacity_at(depth - 1);
        Self::reserve_node(&mut children[index / span], depth - 1, index % span)
    }

    /// Metadata-only growth may remain on refusal; no element or logical length is published.
    pub(super) fn try_reserve(&mut self, additional: usize) -> Result<(), ()> {
        let end = self.len.checked_add(additional).ok_or(())?;
        if Self::leaf_capacity() == 0 || Self::fanout() < 2 {
            return Err(());
        }
        for index in self.len..end {
            while index >= Self::capacity_at(self.depth) {
                let mut children = Self::branch()?;
                children[0] = core::mem::replace(&mut self.root, Node::Empty);
                self.root = Node::Branch(children);
                self.depth += 1;
            }
            Self::reserve_node(&mut self.root, self.depth, index)?;
        }
        Ok(())
    }

    fn leaf(node: &Node<T>, depth: usize, index: usize) -> Option<&Vec<T>> {
        if depth == 0 {
            return match node {
                Node::Leaf(values) => Some(values),
                _ => None,
            };
        }
        let Node::Branch(children) = node else {
            return None;
        };
        let span = Self::capacity_at(depth - 1);
        Self::leaf(children.get(index / span)?, depth - 1, index % span)
    }

    fn leaf_mut(node: &mut Node<T>, depth: usize, index: usize) -> Option<&mut Vec<T>> {
        if depth == 0 {
            return match node {
                Node::Leaf(values) => Some(values),
                _ => None,
            };
        }
        let Node::Branch(children) = node else {
            return None;
        };
        let span = Self::capacity_at(depth - 1);
        Self::leaf_mut(children.get_mut(index / span)?, depth - 1, index % span)
    }

    pub(super) fn get(&self, index: usize) -> Option<&T> {
        if index >= self.len {
            return None;
        }
        Self::leaf(&self.root, self.depth, index)?.get(index % Self::leaf_capacity())
    }

    pub(super) fn get_mut(&mut self, index: usize) -> Option<&mut T> {
        if index >= self.len {
            return None;
        }
        Self::leaf_mut(&mut self.root, self.depth, index)?.get_mut(index % Self::leaf_capacity())
    }

    pub(super) fn iter(&self) -> impl ExactSizeIterator<Item = &T> + DoubleEndedIterator {
        (0..self.len).map(|index| self.get(index).expect("published metadata element"))
    }

    /// Caller must reserve before publishing ownership or performing native effects.
    pub(super) fn push(&mut self, value: T) {
        let leaf = Self::leaf_mut(&mut self.root, self.depth, self.len)
            .expect("metadata capacity reserved before publication");
        assert!(leaf.len() < leaf.capacity());
        leaf.push(value);
        self.len += 1;
    }

    pub(super) fn pop(&mut self) -> Option<T> {
        let index = self.len.checked_sub(1)?;
        let value = Self::leaf_mut(&mut self.root, self.depth, index)?.pop();
        self.len = index;
        value
    }

    pub(super) fn swap_remove(&mut self, index: usize) -> T {
        assert!(index < self.len);
        let last = self.pop().expect("last published element");
        if index == self.len {
            last
        } else {
            core::mem::replace(&mut self[index], last)
        }
    }

    pub(super) fn binary_search_by_key<K: Ord>(
        &self,
        key: &K,
        mut f: impl FnMut(&T) -> K,
    ) -> Result<usize, usize> {
        let mut low = 0;
        let mut high = self.len;
        while low < high {
            let middle = low + (high - low) / 2;
            match f(&self[middle]).cmp(key) {
                core::cmp::Ordering::Less => low = middle + 1,
                core::cmp::Ordering::Greater => high = middle,
                core::cmp::Ordering::Equal => return Ok(middle),
            }
        }
        Err(low)
    }

    #[cfg(test)]
    pub(super) fn visit_allocations(&self, mut visit: impl FnMut(bool, usize, usize)) {
        fn walk<T>(node: &Node<T>, visit: &mut impl FnMut(bool, usize, usize)) {
            match node {
                Node::Empty => {}
                Node::Leaf(values) => visit(
                    true,
                    values.len(),
                    values.capacity() * core::mem::size_of::<T>(),
                ),
                Node::Branch(children) => {
                    visit(
                        false,
                        children.len(),
                        children.capacity() * core::mem::size_of::<Node<T>>(),
                    );
                    for child in children {
                        walk(child, visit);
                    }
                }
            }
        }
        walk(&self.root, &mut visit);
    }
}

impl<T: Copy> PageSequence<T> {
    pub(super) fn insert(&mut self, index: usize, value: T) {
        assert!(index <= self.len);
        let old_len = self.len;
        self.push(value);
        for position in (index..old_len).rev() {
            self[position + 1] = self[position];
        }
        self[index] = value;
    }

    pub(super) fn remove(&mut self, index: usize) -> T {
        let value = self[index];
        for position in index + 1..self.len {
            self[position - 1] = self[position];
        }
        self.pop();
        value
    }
}

impl<T> Index<usize> for PageSequence<T> {
    type Output = T;
    fn index(&self, index: usize) -> &T {
        self.get(index).expect("metadata index")
    }
}

impl<T> IndexMut<usize> for PageSequence<T> {
    fn index_mut(&mut self, index: usize) -> &mut T {
        self.get_mut(index).expect("metadata index")
    }
}

#[cfg(test)]
#[path = "provider_alias_storage_tests.rs"]
mod tests;
