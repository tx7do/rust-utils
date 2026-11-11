//! 切片辅助:查找族、集合运算、去重、分块与子树收集。
//!
//! 运行:`cargo run --example sliceutil`

use rust_utils::sliceutil;

fn main() {
    let nums = [1, 2, 3, 2, 4, 2, 5];
    println!("includes 3: {}", sliceutil::includes(&nums, &3));
    println!(
        "find_indexes_of 2: {:?}",
        sliceutil::find_indexes_of(&nums, &2)
    );
    println!("unique: {:?}", sliceutil::unique(&[3, 1, 3, 2, 1]));

    println!(
        "intersection: {:?}",
        sliceutil::intersection(&[&[1, 2, 3, 4], &[3, 4, 5]])
    );
    println!(
        "difference: {:?}",
        sliceutil::difference(&[&[1, 2, 3, 4], &[3, 4, 5]])
    );
    println!("union: {:?}", sliceutil::union(&[&[1, 2], &[2, 3]]));

    println!("chunk 3: {:?}", sliceutil::chunk(&[1, 2, 3, 4, 5], 3));
    println!("flatten: {:?}", sliceutil::flatten(&[vec![1, 2], vec![3]]));

    // (id, parent_id) 行收集子树(通用 id 类型,根自身含在结果内)
    let rows = [
        (1u64, None),
        (2, Some(1u64)),
        (3, Some(1)),
        (4, Some(2)),
        (9, Some(0)),
    ];
    println!(
        "subtree of 1: {:?}",
        sliceutil::collect_subtree_ids(&rows, 1)
    );

    assert_eq!(sliceutil::find_indexes_of(&nums, &2), vec![1, 3, 5]);
    let subtree = sliceutil::collect_subtree_ids(&rows, 1);
    assert_eq!(subtree.len(), 4);
    println!("OK");
}
