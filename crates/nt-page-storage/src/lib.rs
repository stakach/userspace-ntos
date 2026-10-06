//! Fallible page-bounded metadata storage. Directory growth never relocates leaf elements.
#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use core::ops::{Index, IndexMut};

const PAGE_BYTES: usize = 4096;

enum Node<T> {
    Empty,
    Leaf(Vec<T>),
    Branch(Vec<Node<T>>),
}

pub struct PageSequence<T> {
    root: Node<T>,
    depth: usize,
    len: usize,
}

impl<T> PageSequence<T> {
    pub const fn new() -> Self {
        Self {
            root: Node::Empty,
            depth: 0,
            len: 0,
        }
    }

    pub const fn leaf_capacity() -> usize {
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

    pub fn len(&self) -> usize {
        self.len
    }
    pub fn is_empty(&self) -> bool {
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
    pub fn try_reserve(&mut self, additional: usize) -> Result<(), ()> {
        let end = self.len.checked_add(additional).ok_or(())?;
        if Self::leaf_capacity() == 0 || Self::fanout() < 2 {
            return Err(());
        }
        // Preserve Vec-compatible logical extent admission before allocating the segmented tree.
        end.checked_mul(core::mem::size_of::<T>())
            .filter(|bytes| *bytes <= isize::MAX as usize)
            .ok_or(())?;
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

    pub fn get(&self, index: usize) -> Option<&T> {
        if index >= self.len {
            return None;
        }
        Self::leaf(&self.root, self.depth, index)?.get(index % Self::leaf_capacity())
    }

    pub fn get_mut(&mut self, index: usize) -> Option<&mut T> {
        if index >= self.len {
            return None;
        }
        Self::leaf_mut(&mut self.root, self.depth, index)?.get_mut(index % Self::leaf_capacity())
    }

    pub fn iter(&self) -> impl ExactSizeIterator<Item = &T> + DoubleEndedIterator {
        (0..self.len).map(|index| self.get(index).expect("published metadata element"))
    }

    /// Traverse disjoint leaf elements without allocating iterator bookkeeping.
    pub fn iter_mut(&mut self) -> impl ExactSizeIterator<Item = &mut T> {
        IterMut::new(&mut self.root, self.len)
    }

    pub fn truncate(&mut self, len: usize) {
        while self.len > len {
            drop(self.pop());
        }
    }

    /// Reserve every new slot before generating or publishing any new element.
    pub fn try_resize_with(
        &mut self,
        new_len: usize,
        mut generate: impl FnMut() -> T,
    ) -> Result<(), ()> {
        if new_len <= self.len {
            self.truncate(new_len);
            return Ok(());
        }
        self.try_reserve(new_len - self.len)?;
        while self.len < new_len {
            self.push(generate());
        }
        Ok(())
    }

    pub fn resize_with(&mut self, new_len: usize, generate: impl FnMut() -> T) {
        self.try_resize_with(new_len, generate)
            .expect("page sequence resize allocation failed");
    }

    /// Caller must reserve before publishing ownership or performing native effects.
    pub fn push(&mut self, value: T) {
        let leaf = Self::leaf_mut(&mut self.root, self.depth, self.len)
            .expect("metadata capacity reserved before publication");
        assert!(leaf.len() < leaf.capacity());
        leaf.push(value);
        self.len += 1;
    }

    pub fn pop(&mut self) -> Option<T> {
        let index = self.len.checked_sub(1)?;
        let value = Self::leaf_mut(&mut self.root, self.depth, index)?.pop();
        self.len = index;
        value
    }

    pub fn swap_remove(&mut self, index: usize) -> T {
        assert!(index < self.len);
        let last = self.pop().expect("last published element");
        if index == self.len {
            last
        } else {
            core::mem::replace(&mut self[index], last)
        }
    }

    pub fn binary_search_by_key<K: Ord>(
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

    #[cfg(any(test, feature = "allocation-observation"))]
    pub fn visit_allocations(&self, mut visit: impl FnMut(bool, usize, usize)) {
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

// IterMut retains only sibling iterators while descending, so every mutable reference is disjoint.
// A directory's fanout is at least two; a usize-indexed tree cannot exceed usize::BITS ancestors.
struct IterMut<'a, T> {
    branches: [Option<core::slice::IterMut<'a, Node<T>>>; usize::BITS as usize],
    depth: usize,
    leaf: Option<core::slice::IterMut<'a, T>>,
    remaining: usize,
}

impl<'a, T> IterMut<'a, T> {
    fn new(root: &'a mut Node<T>, len: usize) -> Self {
        let mut iterator = Self {
            branches: core::array::from_fn(|_| None),
            depth: 0,
            leaf: None,
            remaining: len,
        };
        match root {
            Node::Empty => {}
            Node::Leaf(values) => iterator.leaf = Some(values.iter_mut()),
            Node::Branch(children) => {
                iterator.branches[0] = Some(children.iter_mut());
                iterator.depth = 1;
            }
        }
        iterator
    }
}

impl<'a, T> Iterator for IterMut<'a, T> {
    type Item = &'a mut T;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        loop {
            if let Some(value) = self.leaf.as_mut().and_then(|leaf| leaf.next()) {
                self.remaining -= 1;
                return Some(value);
            }
            self.leaf = None;
            let level = self.depth.checked_sub(1)?;
            let next = self.branches[level]
                .as_mut()
                .expect("active directory iterator")
                .next();
            match next {
                None => {
                    self.branches[level] = None;
                    self.depth = level;
                }
                Some(Node::Empty) => {}
                Some(Node::Leaf(values)) => self.leaf = Some(values.iter_mut()),
                Some(Node::Branch(children)) => {
                    self.branches[self.depth] = Some(children.iter_mut());
                    self.depth += 1;
                }
            }
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

impl<T> ExactSizeIterator for IterMut<'_, T> {}

impl<T: Clone> PageSequence<T> {
    /// Clone logical elements into separately reserved page-bounded backing storage.
    pub fn try_clone(&self) -> Result<Self, ()> {
        let mut cloned = Self::new();
        if self.len != 0 {
            cloned.try_reserve(self.len)?;
        }
        for value in self.iter() {
            cloned.push(value.clone());
        }
        Ok(cloned)
    }
}

impl<T: Clone> Clone for PageSequence<T> {
    fn clone(&self) -> Self {
        self.try_clone()
            .expect("page sequence clone allocation failed")
    }
}

impl<T: Copy> PageSequence<T> {
    pub fn insert(&mut self, index: usize, value: T) {
        assert!(index <= self.len);
        let old_len = self.len;
        self.push(value);
        for position in (index..old_len).rev() {
            self[position + 1] = self[position];
        }
        self[index] = value;
    }

    pub fn remove(&mut self, index: usize) -> T {
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
#[path = "tests.rs"]
mod tests;
