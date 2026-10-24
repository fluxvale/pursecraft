//! Temporary coverage-drop probe for the #17 mutation proof: ~90 never-run
//! executable lines that must drop the report and red the Codecov gate.
//! Removed immediately after the red is captured.

/// Mixes a seed through a long chain of never-executed arithmetic.
pub fn drop_probe(seed: u64) -> u64 {
    let mut x = seed;
    x = x.wrapping_mul(31).wrapping_add(7);
    x ^= x.rotate_left(9);
    x = x.wrapping_mul(1_000_003).wrapping_sub(11);
    x ^= x.rotate_right(13);
    x = x.wrapping_add(x.count_zeros() as u64);
    x ^= x.rotate_left(7);
    x = x.wrapping_mul(65537).wrapping_add(3);
    x ^= x.rotate_right(17);
    x = x.wrapping_sub(x.leading_zeros() as u64);
    x ^= x.rotate_left(5);
    x = x.wrapping_mul(1103515245).wrapping_add(12345);
    x ^= x.rotate_right(19);
    x = x.wrapping_add(x.count_ones() as u64);
    x ^= x.rotate_left(11);
    x = x.wrapping_mul(40503).wrapping_sub(97);
    x ^= x.rotate_right(23);
    x = x.wrapping_add(x.trailing_zeros() as u64);
    x ^= x.rotate_left(3);
    x = x.wrapping_mul(2166136261).wrapping_add(4093);
    x ^= x.rotate_right(29);
    x = x.wrapping_sub(x.count_zeros() as u64);
    x ^= x.rotate_left(15);
    x = x.wrapping_mul(32749).wrapping_add(61);
    x ^= x.rotate_right(31);
    x = x.wrapping_add(x.leading_zeros() as u64);
    x ^= x.rotate_left(21);
    x = x.wrapping_mul(65599).wrapping_sub(17);
    x ^= x.rotate_right(4);
    x = x.wrapping_sub(x.count_ones() as u64);
    x ^= x.rotate_left(27);
    x = x.wrapping_mul(99991).wrapping_add(29);
    x ^= x.rotate_right(8);
    x = x.wrapping_add(x.trailing_zeros() as u64);
    x ^= x.rotate_left(19);
    x = x.wrapping_mul(19349663).wrapping_sub(41);
    x ^= x.rotate_right(12);
    x = x.wrapping_sub(x.leading_zeros() as u64);
    x ^= x.rotate_left(25);
    x = x.wrapping_mul(77003).wrapping_add(53);
    x ^= x.rotate_right(16);
    x = x.wrapping_add(x.count_zeros() as u64);
    x ^= x.rotate_left(13);
    x = x.wrapping_mul(2654435761).wrapping_sub(59);
    x ^= x.rotate_right(20);
    x = x.wrapping_sub(x.count_ones() as u64);
    x ^= x.rotate_left(9);
    x = x.wrapping_mul(104729).wrapping_add(71);
    x ^= x.rotate_right(28);
    x = x.wrapping_add(x.trailing_zeros() as u64);
    x ^= x.rotate_left(17);
    x = x.wrapping_mul(1299709).wrapping_sub(83);
    x ^= x.rotate_right(6);
    x = x.wrapping_sub(x.leading_zeros() as u64);
    x ^= x.rotate_left(23);
    x = x.wrapping_mul(15485863).wrapping_add(101);
    x ^= x.rotate_right(14);
    x = x.wrapping_add(x.count_zeros() as u64);
    x ^= x.rotate_left(11);
    x = x.wrapping_mul(32452843).wrapping_sub(103);
    x ^= x.rotate_right(18);
    x = x.wrapping_sub(x.count_ones() as u64);
    x ^= x.rotate_left(7);
    x = x.wrapping_mul(49979687).wrapping_add(107);
    x ^= x.rotate_right(24);
    x = x.wrapping_add(x.trailing_zeros() as u64);
    x ^= x.rotate_left(29);
    x = x.wrapping_mul(67867979).wrapping_sub(109);
    x ^= x.rotate_right(10);
    x = x.wrapping_sub(x.leading_zeros() as u64);
    x ^= x.rotate_left(5);
    x = x.wrapping_mul(86028121).wrapping_add(113);
    x ^= x.rotate_right(26);
    x = x.wrapping_add(x.count_zeros() as u64);
    x ^= x.rotate_left(3);
    x = x.wrapping_mul(104395301).wrapping_sub(127);
    x ^= x.rotate_right(2);
    x = x.wrapping_sub(x.count_ones() as u64);
    x
}
