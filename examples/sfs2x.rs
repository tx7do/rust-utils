//! SFS2X 二进制协议:对象编解码、帧封装、压缩加密与消息信封。
//!
//! 运行:`cargo run --features sfs2x --example sfs2x`

use rust_utils::sfs2x::{
    self, controller, decode_frame, encode_frame, encode_frame_with_options, new_message,
    sys_action, FrameOptions, Message, Object, Value,
};

fn main() {
    // 1. 类型化对象:变体即类型码,同 key 覆盖保持首插位置
    let mut params = Object::new();
    params.put("zone", Value::utf_string("lobby"));
    params.put("reconnect", Value::Bool(false));
    params.put("uid", Value::Long(1234567890123));
    params.put("score", Value::Double(98.76));
    params.put("flags", Value::BoolArray(vec![true, false, true]));

    let mut envelope = Object::new();
    envelope.put("c", Value::Byte(controller::SYSTEM));
    envelope.put("a", Value::Short(sys_action::LOGIN));
    envelope.put("p", Value::SfsObject(params));

    // 2. 帧封装:明文帧确定性(同内容不同插入序 → 逐字节相同)
    let frame = encode_frame(&envelope);
    let decoded = decode_frame(&frame).unwrap();
    let p = decoded.get_object("p").unwrap();
    println!(
        "frame {} bytes, zone={:?}, uid={}",
        frame.len(),
        p.get_string("zone"),
        p.get_long("uid").unwrap()
    );

    // 3. zlib 压缩(阈值可配,官方客户端缺省 1024):帧头 0x20,解码透明解压
    let compressed = sfs2x::encode_frame_with_options(
        &envelope,
        &FrameOptions {
            compress_threshold: 64,
            ..FrameOptions::default()
        },
    )
    .unwrap();
    println!(
        "compressed: {} → {} bytes, 0x20={}",
        frame.len(),
        compressed.len(),
        compressed[0] & sfs2x::COMPRESSION_MASK != 0
    );
    let back = decode_frame(&compressed).unwrap();
    assert_eq!(back.get_long("uid"), decoded.get_long("uid"));

    // 4. AES-128-CBC 加密,官方固定 key+IV 模式(载荷只有密文,确定性);
    //    不给 IV 则为随机 IV 自描述模式(IV 前缀,非确定)
    let key = [0xAB_u8; 16];
    let iv = [0x11_u8; 16];
    let encrypted =
        encode_frame_with_options(&envelope, &FrameOptions::encrypted(&key, &iv)).unwrap();
    let opened =
        sfs2x::decode_frame_with_options(&encrypted, &FrameOptions::encrypted(&key, &iv)).unwrap();
    println!(
        "encrypted: {} bytes, 0x40={}, roundtrip uid={}",
        encrypted.len(),
        encrypted[0] & sfs2x::ENCRYPTION_MASK != 0,
        opened.get_object("p").unwrap().get_long("uid").unwrap()
    );

    // 5. 消息信封({c, a, p})与解析:插入手册字段名
    let msg: Message = new_message(controller::SYSTEM, sys_action::HANDSHAKE, {
        let mut hp = Object::new();
        hp.put(sfs2x::handshake_key::API, Value::utf_string("1.7.3"));
        hp.put(
            sfs2x::handshake_key::CLIENT_TYPE,
            Value::utf_string("RustClient/0.2"),
        );
        hp
    });
    let handshake_frame = msg.encode_ordered_frame().unwrap();
    let parsed = sfs2x::parse_message(&handshake_frame).unwrap();
    println!(
        "handshake: controller={} action={} api={:?}",
        parsed.controller,
        parsed.action,
        parsed.params.get_string(sfs2x::handshake_key::API),
    );

    // 6. 握手应答解析(tk 缺失即报错,fail-fast)
    let mut resp = Object::new();
    resp.put(
        sfs2x::handshake_key::SESSION_TOKEN,
        Value::utf_string("sess-token-1"),
    );
    resp.put(sfs2x::handshake_key::COMPRESSION, Value::Int(1024));
    let hs = sfs2x::parse_handshake_response(&resp).unwrap();
    println!(
        "handshake response: token={:?}, ct={}",
        hs.session_token, hs.compression_threshold
    );

    // 7. 官方 CLASS 约定($C/$F)识别
    let mut class_obj = Object::new();
    class_obj.put(
        sfs2x::CLASS_MARKER_KEY,
        Value::utf_string("com.example.dto.Player"),
    );
    class_obj.put(
        sfs2x::CLASS_FIELDS_KEY,
        Value::SfsArray(vec![Value::Int(7), Value::utf_string("hero")]),
    );
    if let Some((name, fields)) = sfs2x::as_class(Some(&class_obj)) {
        println!("class {name} with {} field(s)", fields.len());
    }
}
