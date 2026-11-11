//! 敏感词过滤:命中检测、区间定位与打码(词典树,纯 std)。
//!
//! 运行:`cargo run --example sensitive`

use rust_utils::sensitive::SensitiveFilter;

fn main() {
    let filter = SensitiveFilter::builder()
        .words(["敏感词", "badword", "spam"])
        .case_insensitive() // ASCII 大小写不敏感
        .ignore_chars(['*', ' ', '-']) // "敏*感*词" 也能命中
        .build();

    let texts = [
        "正常内容,无需处理",
        "这句里有敏感词,拦下",
        "bAd-WoRd 也要拦截",
        "敏*感*词 变体照打",
    ];
    for t in texts {
        let hits = filter.find_all(t);
        let masked = filter.mask(t, '*');
        println!("{t:?} → hits: {} → {masked}", hits.len());
    }

    assert!(!filter.is_hit("正常内容,无需处理"));
    assert!(filter.is_hit("这句里有敏感词,拦下"));
    assert_eq!(filter.mask("这句里有敏感词,拦下", '*'), "这句里有***,拦下");
    assert_eq!(filter.mask("bAd-WoRd x", '*'), "******** x"); // 穿插的 - 计入区间
    println!("OK");
}
