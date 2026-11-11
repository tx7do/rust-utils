//! 进程内事件总线:订阅/发布 + 多总线管理(纯 std,无 async 运行时)。
//!
//! 运行:`cargo run --example eventbus`

use std::sync::Arc;

use rust_utils::eventbus::{Event, Manager};

fn main() {
    let manager = Manager::new();
    let counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));

    // 订阅全局总线(闭包经 blanket impl 自动成为 Handler)
    let c = counter.clone();
    manager
        .subscribe_global(
            "user.created",
            Arc::new(move |_event: &Event| {
                c.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok(())
            }),
        )
        .unwrap();

    // 发布:同一事件可携带数据/来源/优先级
    let event = Event::new("user.created", Some(r#"{"id": 1001}"#.to_string()))
        .with_source("user-service")
        .with_priority(5);
    manager.publish_global(&event).unwrap();
    assert_eq!(counter.load(std::sync::atomic::Ordering::SeqCst), 1);
    println!(
        "handled: {} event(s)",
        counter.load(std::sync::atomic::Ordering::SeqCst)
    );

    // 多总线:业务隔离(各自订阅者互不可见)
    manager
        .subscribe(
            "billing",
            "order.paid",
            Arc::new(|e: &Event| {
                println!("[billing] order paid: {:?}", e.data());
                Ok(())
            }),
        )
        .unwrap();
    manager
        .publish(
            "billing",
            &Event::new("order.paid", Some("ORD-1".to_string())),
        )
        .unwrap();
    // 订阅数在总线本体上查询(Manager 只做分派)
    let billing = manager.get_bus("billing");
    assert_eq!(billing.subscriber_count("order.paid"), 1);

    // 处理器报错不影响其余处理器(与上游 Go 语义一致)
    manager
        .subscribe_global("flake", Arc::new(|_: &Event| Err("boom".into())))
        .unwrap();
    manager
        .subscribe_global("flake", Arc::new(|_: &Event| Ok(())))
        .unwrap();
    manager.publish_global(&Event::new("flake", None)).unwrap();

    println!("OK");
}
