use sha2::{Sha256, Digest};
use std::borrow::{Borrow, BorrowMut};
use std::cmp::min;
use std::rc::Rc;
use std::cell::RefCell;

// https://github.com/celestiaorg/go-square/blob/main/merkle/proof.go#L232

#[derive(Clone)]
struct ProofNode {
    hash: Rc<RefCell<[u8; 32]>>,
    parent: Option<Rc<RefCell<ProofNode>>>,
    left: Option<Rc<RefCell<ProofNode>>>,
    right: Option<Rc<RefCell<ProofNode>>>,
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
    length / 2
}

pub fn trails_from_byte_slices(items: &[&[u8]]) -> (Vec<Rc<RefCell<ProofNode>>>, Rc<RefCell<ProofNode>>) {
    match items.len() {
        0 => return (
            vec![], 
            Rc::new(RefCell::new(ProofNode{
                hash: Rc::new(RefCell::new(empty_hash())),
                parent: None,
                left: None,
                right: None,
            }))
        ),
        1 => return (
            vec![Rc::new(RefCell::new(ProofNode{
                hash: Rc::new(RefCell::new(leaf_hash(items[0]))),
                parent: None,
                left: None,
                right: None,
            }))],
            Rc::new(RefCell::new(ProofNode{
                hash: Rc::new(RefCell::new(leaf_hash(items[0]))),
                parent: None,
                left: None,
                right: None,
            }))
        ),
        _ => {
            let split_point = get_split_point(items.len() as u32);
            let (lefts, left_root) = trails_from_byte_slices(&items[..split_point as usize]);
            let (rights, right_root) = trails_from_byte_slices(&items[split_point as usize..]);
            /*let root_hash = inner_hash(
                &left_root.borrow().hash.borrow()[..],
                &right_root.borrow().hash.borrow()[..],
            );
            let root = Rc::new(RefCell::new(ProofNode{
                hash: root_hash,
                parent: None,
                left: None,
                right: None,
            }));
            //left_root.clone().get_mut().parent = Some(root.clone());
            return (vec![lefts, rights].concat(), root);*/
            return (vec![], Rc::new(RefCell::new(ProofNode{
                hash: Rc::new(RefCell::new([0; 32])),
                parent: None,
                left: None,
                right: None,
            })))
        },
    }
}