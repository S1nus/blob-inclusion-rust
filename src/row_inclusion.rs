use sha2::{Sha256, Digest};
use std::borrow::{Borrow, BorrowMut};
use std::cmp::min;
use std::rc::{Rc, Weak};
use std::cell::RefCell;

#[derive(Clone, Debug)]
pub struct ProofNode {
    pub hash: [u8; 32],
    pub parent: Option<Rc<RefCell<ProofNode>>>,
    pub left: Option<Rc<RefCell<ProofNode>>>,
    pub right: Option<Rc<RefCell<ProofNode>>>,
}

pub const LEAF_PREFIX: &[u8] = &[0];
pub const INNER_PREFIX: &[u8] = &[1];

pub fn hash(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let result: [u8; 32] = hasher.finalize().into();
    result
}

pub fn empty_hash() -> [u8; 32] {
    hash(&[])
}

pub fn leaf_hash(bytes: &[u8]) -> [u8; 32] {
    hash([LEAF_PREFIX, bytes].concat().as_slice())
}

pub fn inner_hash(left: &[u8], right: &[u8]) -> [u8; 32] {
    hash([INNER_PREFIX, left, right].concat().as_slice())
}

// rewrite this to arithetic-based computation
// make it easier for zk prover
fn get_split_point(length: u32) -> u32 {
    length.next_power_of_two() / 2
}

pub fn hash_from_byte_slices(items: &[&[u8]]) -> [u8; 32] {
    match items.len() {
        0 => empty_hash(),
        1 => leaf_hash(items[0]),
        _ => {
            let k: u32 = get_split_point(items.len() as u32);
            let left_hash = hash_from_byte_slices(&items[..k as usize]);
            let right_hash = hash_from_byte_slices(&items[k as usize..]);
            inner_hash(&left_hash, &right_hash)
        }
    }
}

pub fn trails_from_byte_slices(items: &[&[u8]]) -> (Vec<Rc<RefCell<ProofNode>>>, Rc<RefCell<ProofNode>>) {
    match items.len() {
        0 => (vec![], Rc::new(RefCell::new(ProofNode {
            hash: empty_hash(),
            parent: None,
            left: None,
            right: None,
        }))),
        1 => {
            let leaf_hash = leaf_hash(items[0]);
            let trail = Rc::new(RefCell::new(ProofNode {
                hash: leaf_hash,
                parent: None,
                left: None,
                right: None,
            }));
            (vec![trail.clone()], trail)
        }
        _ => {
            let k: u32 = get_split_point(items.len() as u32);
            let (lefts, mut left_root) = trails_from_byte_slices(&items[..k as usize]);
            let (rights, mut right_root) = trails_from_byte_slices(&items[k as usize..]);

            // compute the inner_hash of the left_root and right_roots
            let root_hash = inner_hash(&left_root.as_ref().borrow().hash, &right_root.as_ref().borrow().hash);
            let root_node = Rc::new(RefCell::new(ProofNode {
                hash: root_hash,
                parent: None,
                left: None,
                right: None,
            }));

            // update the parent of the left and right roots
            let mut l = left_root.as_ref().borrow_mut();
            l.parent = Some(root_node.clone());
            l.right = Some(right_root.clone());
            let mut r = right_root.as_ref().borrow_mut();
            r.parent = Some(root_node.clone());
            r.left = Some(left_root.clone());

            return (vec![lefts, rights].concat(), root_node)
        }
    }
}

impl ProofNode {
    pub fn flatten_aunts(&self) -> Vec<[u8; 32]> {
        let mut inner_hashes: Vec<[u8; 32]> = vec![];
        let mut node: Option<Rc<RefCell<ProofNode>>> = Some(Rc::new(RefCell::new(self.clone())));
        while let Some(n) = node.take() {
            // if node has a left, add its hash to inner_hashes
            if let Some(left) = &n.as_ref().borrow().left {
                let left_hash = left.as_ref().borrow().hash.clone();
                inner_hashes.push(left_hash);
            }
            if let Some(right) = &n.as_ref().borrow().right {
                let right_hash = right.as_ref().borrow().hash.clone();
                inner_hashes.push(right_hash);
            }
            node = n.as_ref().borrow().parent.clone();
        }
        inner_hashes
    }
}