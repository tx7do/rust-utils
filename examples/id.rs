//! 雪花 ID、订单号与机器码。
//!
//! 运行:`cargo run --features uuid --example id`

use rust_utils::id;

fn main() {
    // 雪花 ID(单节点便捷入口;常驻服务请用 SnowflakeNode)
    let id1 = id::generate_snowflake_id(1);
    let id2 = id::generate_snowflake_id(1);
    assert!(id2 > id1, "同节点单调递增");
    println!("snowflake: {id1} → {id2}");

    // 订单号:时间前缀 + 随机尾
    let order = id::generate_order_id_with_random("ORD", None);
    println!("order id:  {order}");
    assert!(order.starts_with("ORD"));

    // 机器码(跨平台主板/系统指纹,归一化后稳定)
    let machine = id::unify_machine_id().unwrap();
    println!(
        "machine:   {}…(len {})",
        &machine[..12.min(machine.len())],
        machine.len()
    );

    // 短 UUID(小写字母数字)
    let short = id::new_short_uuid();
    println!("short id:  {short}");

    println!("OK");
}
