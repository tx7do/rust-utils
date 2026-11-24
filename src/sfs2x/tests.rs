//! 对位上游 go-utils/sfs2x 全部测试(sfs2x_test / features_test /
//! golden_test),外加全截断/单字节翻转的"绝不 panic"扫描。
//!
//! 黄金向量(assets/sfs2x/)来自 ZewSFS Python 参考实现,断言解码值与
//! manifest 逐键一致 + 重编码字节级一致;资产缺失时自动跳过(与
//! assets/geoip、assets/jwt 同款约定)。

use super::*;
use std::path::PathBuf;

fn assets_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("assets")
        .join("sfs2x")
}

// ============================================================
// 基础编解码回环
// ============================================================

#[test]
fn test_encode_decode_roundtrip() {
    let mut inner = Object::new();
    inner.put("resourceId", Value::utf_string("22048"));
    inner.put("sessionToken", Value::utf_string("session-abc-1"));

    let mut outer = Object::new();
    outer.put("c", Value::Byte(0));
    outer.put("a", Value::Short(0));
    outer.put("p", Value::SfsObject(inner));

    let encoded = outer.encode();
    let decoded = decode(&encoded).unwrap();
    assert_eq!(decoded.get_byte("c"), Some(0));
    assert_eq!(decoded.get_short("a"), Some(0));
    let p = decoded.get_object("p").expect("p is nil");
    assert_eq!(p.get_string("resourceId"), Some("22048"));
}

#[test]
fn test_encode_types() {
    let mut o = Object::new();
    o.put("b", Value::Bool(true));
    o.put("by", Value::Byte(42));
    o.put("s", Value::Short(1000));
    o.put("i", Value::Int(100000));
    o.put("l", Value::Long(9999999999));
    o.put("d", Value::Double(98.76));
    o.put("str", Value::utf_string("hello world"));
    o.put("nil", Value::Null);

    let decoded = decode(&o.encode()).unwrap();
    assert_eq!(decoded.get("b"), Some(&Value::Bool(true)));
    assert_eq!(decoded.get("by"), Some(&Value::Byte(42)));
    assert_eq!(decoded.get("i"), Some(&Value::Int(100000)));
    assert_eq!(decoded.get("str"), Some(&Value::utf_string("hello world")));
    assert_eq!(decoded.get("nil"), Some(&Value::Null));
}

#[test]
fn test_nested_sfs_object() {
    let mut inner = Object::new();
    inner.put("key", Value::utf_string("value"));
    let mut mid = Object::new();
    mid.put("inner", Value::SfsObject(inner));
    let mut outer = Object::new();
    outer.put("mid", Value::SfsObject(mid));

    let decoded = decode(&outer.encode()).unwrap();
    let inner_d = decoded
        .get_object("mid")
        .and_then(|m| m.get_object("inner"))
        .expect("nested object missing");
    assert_eq!(inner_d.get_string("key"), Some("value"));
}

// ============================================================
// 帧
// ============================================================

#[test]
fn test_frame_roundtrip() {
    let mut o = Object::new();
    o.put("c", Value::Byte(0));
    o.put("a", Value::Short(0));
    let mut inner = Object::new();
    inner.put("tk", Value::utf_string("token123"));
    inner.put("ms", Value::Int(1000000));
    o.put("p", Value::SfsObject(inner));

    let frame = encode_frame(&o);
    let decoded = decode_frame(&frame).unwrap();
    assert_eq!(decoded.get_byte("c"), Some(0));
    let p = decoded.get_object("p").expect("p nil");
    assert_eq!(p.get_string("tk"), Some("token123"));
    assert_eq!(p.get_int("ms"), Some(1000000));
}

#[test]
fn test_decode_frame_long_length_form() {
    let payload = Object::new().encode();

    // 手工拼装 uint32 长度形态(帧头 bit 0x08)——decode_frame 必须兼容
    let mut buf = vec![SIGNATURE | LONG_LEN_MASK];
    write_u32(&mut buf, payload.len());
    buf.extend_from_slice(&payload);

    let decoded = decode_frame(&buf).unwrap();
    assert_eq!(decoded.get_keys(), Vec::<&str>::new());
}

#[test]
fn test_decode_frame_errors() {
    // 过短
    assert!(
        decode_frame(&[SIGNATURE, 0]).is_err(),
        "short frame must fail"
    );
    // 载荷截断
    let bad = [SIGNATURE, 0x00, 0x10, t::SFS_OBJECT, 0x00];
    assert!(decode_frame(&bad).is_err(), "truncated payload must fail");
    // 非法 marker
    assert!(
        decode(&[0x99, 0x00, 0x00]).is_err(),
        "invalid marker must fail"
    );
}

#[test]
fn test_deterministic_encoding() {
    // 相同内容(不同插入序)必须产出逐字节相同的编码——key 排序保证确定性
    let mut a = Object::new();
    a.put("zz", Value::utf_string("1"));
    a.put("aa", Value::utf_string("2"));

    let mut b = Object::new();
    b.put("aa", Value::utf_string("2"));
    b.put("zz", Value::utf_string("1"));

    assert_eq!(
        a.encode(),
        b.encode(),
        "encoding must be deterministic regardless of insertion order"
    );
    assert_eq!(
        a.get_keys(),
        vec!["zz", "aa"],
        "get_keys must preserve insertion order"
    );
}

/// 走遍富对象的每个截断点——畸形输入必须报错,绝不 panic(解码不可信
/// 字节的库承受不起切片越界崩溃)。
#[test]
fn test_decode_truncated_never_panics() {
    let mut inner = Object::new();
    inner.put("tok", Value::utf_string("abcdefgh"));
    inner.put("blob", Value::ByteArray(vec![1, 2, 3, 4, 5, 6, 7, 8]));
    let mut o = Object::new();
    o.put("b", Value::Bool(true));
    o.put("s", Value::Short(-2));
    o.put("i", Value::Int(-3));
    o.put("l", Value::Long(-4));
    o.put("f", Value::Float(1.5));
    o.put("d", Value::Double(2.5));
    o.put(
        "arr",
        Value::SfsArray(vec![
            Value::Int(1),
            Value::utf_string("x"),
            Value::Bool(true),
        ]),
    );
    o.put("p", Value::SfsObject(inner));
    let full = o.encode();

    for cut in 0..=full.len() {
        let _ = decode(&full[..cut]); // 报错为预期(cut==len 时完整解码)
    }

    // 单字节翻转也不得 panic
    for i in 0..full.len() {
        let mut mutated = full.clone();
        mutated[i] ^= 0xFF;
        let _ = decode(&mutated);
    }
}

/// 载荷超过 uint16 上限时必须自动切换 BIG_SIZE 长形态(0x08 + uint32)
/// ——静默截断会让对端按错误长度读帧。
#[test]
fn test_encode_frame_auto_big_size() {
    let mut o = Object::new();
    o.put("big", Value::ByteArray(vec![0u8; 70000])); // payload > 0xFFFF

    let frame = encode_frame(&o);
    assert!(
        frame[0] & LONG_LEN_MASK != 0,
        "payload {} must switch to BIG_SIZE form, header {:02x}",
        frame.len(),
        frame[0]
    );

    let decoded = decode_frame(&frame).unwrap();
    let blob = decoded.get_byte_array("big").expect("big payload missing");
    assert_eq!(blob.len(), 70000, "big payload roundtrip failed");
}

/// 压缩帧经 decode_frame 透明解压——不再是拒绝语义。
#[test]
fn test_decode_frame_compressed_transparent() {
    let mut inner = Object::new();
    inner.put("blob", Value::ByteArray([7, 8, 9].repeat(512)));
    let mut o = Object::new();
    o.put("p", Value::SfsObject(inner));

    let frame = encode_frame_with_options(
        &o,
        &FrameOptions {
            compress_threshold: 64,
            ..FrameOptions::default()
        },
    )
    .unwrap();
    assert!(
        frame[0] & COMPRESSION_MASK != 0,
        "payload {} over threshold must set 0x20, header {:02x}",
        frame.len(),
        frame[0]
    );

    let decoded = decode_frame(&frame).unwrap(); // 无选项也应透明解压
    let blob = decoded
        .get_object("p")
        .unwrap()
        .get_byte_array("blob")
        .unwrap();
    assert_eq!(blob.len(), 1536);

    // 阈值以内不压缩
    let mut small = Object::new();
    small.put("s", Value::utf_string("hi"));
    let small_frame = encode_frame_with_options(
        &small,
        &FrameOptions {
            compress_threshold: DEFAULT_COMPRESS_THRESHOLD,
            ..FrameOptions::default()
        },
    )
    .unwrap();
    assert!(
        small_frame[0] & COMPRESSION_MASK == 0,
        "small payload must not be compressed"
    );
}

/// 加密帧无钥匙必须显式报错;非二进制帧也必须拒绝。
#[test]
fn test_decode_frame_rejects_flags() {
    let payload = Object::new().encode();

    let build = |hdr: u8| {
        let mut out = vec![hdr, (payload.len() >> 8) as u8, payload.len() as u8];
        out.extend_from_slice(&payload);
        out
    };

    let encrypted = decode_frame(&build(SIGNATURE | ENCRYPTION_MASK)).unwrap_err();
    assert!(encrypted.contains("no decryption key"), "err: {encrypted}");
    let non_binary = decode_frame(&build(COMPRESSION_MASK)).unwrap_err();
    assert!(non_binary.contains("not a binary"), "err: {non_binary}");
}

/// 七个标量数组类型全量回环 + 类型码钉住。
#[test]
fn test_typed_arrays_roundtrip() {
    let mut o = Object::new();
    o.put("ba", Value::BoolArray(vec![true, false, true]));
    o.put("sa", Value::ShortArray(vec![-2, -1, 0, 1, 2]));
    o.put("ia", Value::IntArray(vec![-100000, 0, 100000]));
    o.put("la", Value::LongArray(vec![-9999999999, 0, 9999999999]));
    o.put("fa", Value::FloatArray(vec![1.5, -2.25]));
    o.put("da", Value::DoubleArray(vec![98.76, -0.5]));
    o.put(
        "ua",
        Value::UtfStringArray(vec!["alpha".into(), String::new(), "omega".into()]),
    );

    let decoded = decode(&o.encode()).unwrap();

    assert_eq!(
        decoded.get("ba"),
        Some(&Value::BoolArray(vec![true, false, true]))
    );
    assert_eq!(
        decoded.get("sa"),
        Some(&Value::ShortArray(vec![-2, -1, 0, 1, 2]))
    );
    assert_eq!(
        decoded.get("ia"),
        Some(&Value::IntArray(vec![-100000, 0, 100000]))
    );
    assert_eq!(
        decoded.get("la"),
        Some(&Value::LongArray(vec![-9999999999, 0, 9999999999]))
    );
    match decoded.get("fa") {
        Some(Value::FloatArray(fa)) => {
            assert_eq!(fa.len(), 2);
            assert!((fa[0] - 1.5).abs() < 1e-6);
            assert!((fa[1] - -2.25).abs() < 1e-6);
        }
        other => panic!("fa mismatch: {other:?}"),
    }
    assert_eq!(
        decoded.get("da"),
        Some(&Value::DoubleArray(vec![98.76, -0.5]))
    );
    assert_eq!(
        decoded.get("ua"),
        Some(&Value::UtfStringArray(vec![
            "alpha".into(),
            String::new(),
            "omega".into()
        ]))
    );

    // 类型码钉住:解码后条目类型必须与写入一致
    for (key, want) in [
        ("ba", t::BOOL_ARRAY),
        ("sa", t::SHORT_ARRAY),
        ("ia", t::INT_ARRAY),
        ("la", t::LONG_ARRAY),
        ("fa", t::FLOAT_ARRAY),
        ("da", t::DOUBLE_ARRAY),
        ("ua", t::UTF_STRING_ARRAY),
    ] {
        assert_eq!(decoded.get_type(key), Some(want), "get_type({key})");
    }
}

/// 负数两补数编码必须无损回环。
#[test]
fn test_negative_numbers_roundtrip() {
    let mut o = Object::new();
    o.put("s", Value::Short(-1234));
    o.put("i", Value::Int(-123456));
    o.put("l", Value::Long(-1234567890123));

    let decoded = decode(&o.encode()).unwrap();
    assert_eq!(decoded.get_short("s"), Some(-1234));
    assert_eq!(decoded.get_int("i"), Some(-123456));
    assert_eq!(decoded.get_long("l"), Some(-1234567890123));
}

/// 空对象/空串/空数组边界。
#[test]
fn test_empty_object_and_strings() {
    let empty = Object::new();
    let decoded = decode(&empty.encode()).unwrap();
    assert!(
        decoded.get_keys().is_empty(),
        "empty object must stay empty"
    );

    let mut o = Object::new();
    o.put("e", Value::utf_string(""));
    o.put("ea", Value::UtfStringArray(vec![]));
    o.put("ia", Value::IntArray(vec![]));
    let decoded = decode(&o.encode()).unwrap();
    assert_eq!(decoded.get_string("e"), Some(""));
    assert_eq!(decoded.get("ea"), Some(&Value::UtfStringArray(vec![])));
    assert_eq!(decoded.get("ia"), Some(&Value::IntArray(vec![])));
}

/// 同 key 重复 put 必须覆盖且 keys 去重。
#[test]
fn test_put_overwrite_keeps_single_key() {
    let mut o = Object::new();
    o.put("k", Value::utf_string("first"));
    o.put("k", Value::Int(7));
    o.put("other", Value::Bool(true));

    assert_eq!(o.get_keys(), vec!["k", "other"]);
    let decoded = decode(&o.encode()).unwrap();
    assert_eq!(decoded.get_int("k"), Some(7), "overwrite must win");
}

/// float32 回环位精度。
#[test]
fn test_float32_precision() {
    let mut o = Object::new();
    o.put("f", Value::Float(0.1));
    let decoded = decode(&o.encode()).unwrap();
    assert_eq!(decoded.get("f"), Some(&Value::Float(0.1)));
}

// ============================================================
// 官方固定 key+IV 加密模式
// ============================================================

fn base64_of(key: &[u8], iv: &[u8]) -> String {
    let mut raw = key.to_vec();
    raw.extend_from_slice(iv);
    crate::base64util::encode(&raw)
}

#[test]
fn test_fixed_iv_encryption_official_mode() {
    let ck = parse_crypto_key_response_base64(&base64_of(&[0xAB; 16], &[0x11; 16])).unwrap();

    let mut o = Object::new();
    o.put("cmd", Value::utf_string("secure op"));
    o.put("n", Value::Int(-7));

    // 官方模式:固定 key+IV,载荷只有密文(无 IV 前缀)
    let frame = encode_frame_with_options(&o, &FrameOptions::encrypted(&ck.key, &ck.iv)).unwrap();
    assert!(frame[0] & ENCRYPTION_MASK != 0, "must set 0x40");
    // 自描述模式同一对象:密文长度 = 官方密文 + 16B IV 前缀(IV 在载荷里)
    let self_frame = encode_frame_with_options(
        &o,
        &FrameOptions {
            encryption_key: Some(&ck.key),
            ..FrameOptions::default()
        },
    )
    .unwrap();
    // 帧长度差 = IV 前缀(两模式 padding 相同、长度字段宽度相同)
    assert_eq!(
        self_frame.len() - frame.len(),
        IV_SIZE,
        "self-describing mode should carry +{IV_SIZE} IV prefix"
    );

    // 官方模式回环
    let decoded =
        decode_frame_with_options(&frame, &FrameOptions::encrypted(&ck.key, &ck.iv)).unwrap();
    assert_eq!(decoded.get_string("cmd"), Some("secure op"));
    assert_eq!(decoded.get_int("n"), Some(-7));

    // 固定 IV 模式确定性(同输入同输出——IV 不随机)
    let frame2 = encode_frame_with_options(&o, &FrameOptions::encrypted(&ck.key, &ck.iv)).unwrap();
    assert_eq!(frame, frame2, "fixed-IV mode is deterministic");

    // 官方模式确定性帧错误钥匙 → 报错
    let wrong = parse_crypto_key_response_base64(&base64_of(&[0x01; 16], &[0x02; 16])).unwrap();
    assert!(
        decode_frame_with_options(&frame, &FrameOptions::encrypted(&wrong.key, &wrong.iv)).is_err(),
        "wrong fixed key/iv must fail padding check"
    );
}

#[test]
fn test_parse_crypto_key_response() {
    let key = [0x11u8; 16];
    let iv = [0x22u8; 16];

    let mut raw = key.to_vec();
    raw.extend_from_slice(&iv);
    let ck = parse_crypto_key_response(&raw).unwrap();
    assert_eq!(ck.key, key.to_vec());
    assert_eq!(ck.iv, iv.to_vec());

    let ck = parse_crypto_key_response_base64(&base64_of(&key, &iv)).unwrap();
    assert_eq!(ck.key, key.to_vec());
    assert_eq!(ck.iv, iv.to_vec());

    assert!(
        parse_crypto_key_response(b"short").is_err(),
        "wrong length must fail"
    );
}

// ============================================================
// encode_ordered 插入序字节忠实模式
// ============================================================

#[test]
fn test_encode_ordered_byte_faithful_to_insertion_order() {
    // 插入序 z 在前:encode(排序)与 encode_ordered(插入序)必须产出不同
    // 字节,且各自解码回值一致
    let mut o = Object::new();
    o.put("zz", Value::utf_string("first-inserted"));
    o.put("aa", Value::utf_string("second-inserted"));

    let sorted = o.encode();
    let ordered = o.encode_ordered();
    assert_ne!(sorted, ordered, "two orders must differ");

    // 排序版以 "aa" 开头(sorted 编码首个 key 是 aa)
    assert!(String::from_utf8_lossy(&sorted[..16]).contains("aa"));
    // 插入序版以 "zz" 开头
    assert!(String::from_utf8_lossy(&ordered[..16]).contains("zz"));

    for enc in [&sorted, &ordered] {
        let decoded = decode(enc).unwrap();
        assert_eq!(decoded.get_string("zz"), Some("first-inserted"));
        assert_eq!(decoded.get_string("aa"), Some("second-inserted"));
    }

    // FrameOptions.ordered 走同一插入序路径
    let frame_plain = encode_frame(&o);
    let frame_ordered = encode_frame_with_options(
        &o,
        &FrameOptions {
            ordered: true,
            ..FrameOptions::default()
        },
    )
    .unwrap();

    let mut manual_sorted = vec![SIGNATURE];
    write_u16(&mut manual_sorted, sorted.len());
    manual_sorted.extend_from_slice(&sorted);
    assert_eq!(manual_sorted, frame_plain);

    let mut manual_ordered = vec![SIGNATURE];
    write_u16(&mut manual_ordered, ordered.len());
    manual_ordered.extend_from_slice(&ordered);
    assert_eq!(manual_ordered, frame_ordered);
}

// ============================================================
// as_class($C/$F 官方 CLASS 约定)
// ============================================================

#[test]
fn test_as_class() {
    let mut inner = Object::new();
    inner.put(
        CLASS_MARKER_KEY,
        Value::utf_string("com.example.dto.Player"),
    );
    let fields = vec![Value::Int(7), Value::utf_string("name-x")];
    inner.put(CLASS_FIELDS_KEY, Value::SfsArray(fields.clone()));

    let (class_name, got_fields) = as_class(Some(&inner)).expect("must match class shape");
    assert_eq!(class_name, "com.example.dto.Player");
    assert_eq!(got_fields, fields.as_slice());

    // 回环:含 $C/$F 的对象经编解码后仍被识别
    let decoded = decode(&inner.encode()).unwrap();
    assert!(as_class(Some(&decoded)).is_some());

    // 普通对象不误判
    let mut plain = Object::new();
    plain.put("x", Value::Int(1));
    assert!(as_class(Some(&plain)).is_none());
    assert!(as_class(None).is_none());
}

// ============================================================
// 消息信封
// ============================================================

#[test]
fn test_message_roundtrip() {
    let mut params = Object::new();
    params.put("zone", Value::utf_string("lobby"));
    params.put("reconnect", Value::Bool(false));

    let msg = new_message(controller::SYSTEM, sys_action::LOGIN, params);
    let frame = msg.encode_ordered_frame().unwrap();

    let parsed = parse_message(&frame).unwrap();
    assert_eq!(parsed.controller, controller::SYSTEM);
    assert_eq!(parsed.action, sys_action::LOGIN);
    assert_eq!(parsed.params.get_string("zone"), Some("lobby"));
}

#[test]
fn test_message_envelope_errors() {
    let mut o = Object::new();
    o.put("c", Value::utf_string("wrong-type"));
    assert!(parse_message_object(&o).is_err(), "c 非 BYTE 必须拒绝");
}

// ============================================================
// 握手报文
// ============================================================

#[test]
fn test_handshake_request_shape() {
    let msg = new_handshake_request("1.7.3", "GoClient/1.0");
    assert_eq!(msg.controller, controller::SYSTEM);
    assert_eq!(msg.action, sys_action::HANDSHAKE);
    assert_eq!(msg.params.get_string(handshake_key::API), Some("1.7.3"));
    assert_eq!(
        msg.params.get_string(handshake_key::CLIENT_TYPE),
        Some("GoClient/1.0")
    );
}

#[test]
fn test_parse_handshake_response() {
    let mut resp = Object::new();
    resp.put(
        handshake_key::SESSION_TOKEN,
        Value::utf_string("sess-token-1"),
    );
    resp.put(handshake_key::COMPRESSION, Value::Int(1024));
    resp.put(handshake_key::MAX_MESSAGE, Value::Int(1000000));

    let parsed = parse_handshake_response(&resp).unwrap();
    assert_eq!(parsed.session_token, "sess-token-1");
    assert_eq!(parsed.compression_threshold, 1024);
    assert_eq!(parsed.max_message_size, 1000000);

    // 缺 tk 报错
    assert!(parse_handshake_response(&Object::new()).is_err());
}

// ============================================================
// 加密帧全链路 + 钥匙校验 + 压缩炸弹
// ============================================================

#[test]
fn test_encrypt_decrypt_frame_roundtrip() {
    let key = b"0123456789abcdef"; // 16B

    let mut o = Object::new();
    o.put("str", Value::utf_string("payload for encryption test"));
    o.put("n", Value::Int(-42));

    // 纯加密(自描述模式)
    let frame = encode_frame_with_options(
        &o,
        &FrameOptions {
            encryption_key: Some(key),
            ..FrameOptions::default()
        },
    )
    .unwrap();
    assert!(
        frame[0] & ENCRYPTION_MASK != 0,
        "encrypted frame must set 0x40"
    );

    // 随机 IV:同内容两次编码产出不同字节
    let frame2 = encode_frame_with_options(
        &o,
        &FrameOptions {
            encryption_key: Some(key),
            ..FrameOptions::default()
        },
    )
    .unwrap();
    assert_ne!(
        frame, frame2,
        "random IV must make encrypted frames non-deterministic"
    );

    let decoded = decode_frame_with_options(
        &frame,
        &FrameOptions {
            encryption_key: Some(key),
            ..FrameOptions::default()
        },
    )
    .unwrap();
    assert_eq!(
        decoded.get_string("str"),
        Some("payload for encryption test")
    );
    assert_eq!(decoded.get_int("n"), Some(-42));

    // 无钥匙的 decode_frame 拒绝
    assert!(decode_frame(&frame).is_err());

    // 错钥匙 → 报错不 panic
    let wrong: &[u8] = b"fedcba9876543210";
    assert!(
        decode_frame_with_options(
            &frame,
            &FrameOptions {
                encryption_key: Some(wrong),
                ..FrameOptions::default()
            },
        )
        .is_err(),
        "wrong key must fail"
    );

    // 压缩+加密叠加(先压后加密)
    let mut big = Object::new();
    big.put("blob", Value::ByteArray([1, 2, 3].repeat(512)));
    let joint = encode_frame_with_options(
        &big,
        &FrameOptions {
            compress_threshold: 64,
            encryption_key: Some(key),
            ..FrameOptions::default()
        },
    )
    .unwrap();
    assert!(
        joint[0] & COMPRESSION_MASK != 0 && joint[0] & ENCRYPTION_MASK != 0,
        "joint frame must set both flags, header {:02x}",
        joint[0]
    );
    let decoded_joint = decode_frame_with_options(
        &joint,
        &FrameOptions {
            encryption_key: Some(key),
            ..FrameOptions::default()
        },
    )
    .unwrap();
    assert_eq!(decoded_joint.get_byte_array("blob").unwrap().len(), 1536);
}

#[test]
fn test_encrypt_key_validation() {
    // None = 不加密;Some 但长度不对必须在编码期拒绝
    for bad in [
        &b""[..],
        b"short",
        &[0u8; 15][..],
        &[0u8; 17][..],
        &[0u8; 32][..],
    ] {
        assert!(
            encode_frame_with_options(
                &Object::new(),
                &FrameOptions {
                    encryption_key: Some(bad),
                    ..FrameOptions::default()
                },
            )
            .is_err(),
            "key len {} must be rejected on encode",
            bad.len()
        );
    }

    let key = [0u8; 16];
    let frame = encode_frame_with_options(
        &Object::new(),
        &FrameOptions {
            encryption_key: Some(&key),
            ..FrameOptions::default()
        },
    )
    .unwrap();
    for bad in [None, Some(&b"short"[..])] {
        assert!(
            decode_frame_with_options(
                &frame,
                &FrameOptions {
                    encryption_key: bad,
                    ..FrameOptions::default()
                },
            )
            .is_err(),
            "key {:?} must be rejected on decode",
            bad.map(<[u8]>::len)
        );
    }
}

/// 恶意压缩帧的解压输出必须有上限(防解压炸弹)。
#[test]
fn test_compression_bomb_capped() {
    // 手工构造:超出上限的解压输出。zlib 头 + 压缩的零流
    use std::io::Write;
    let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(&vec![0u8; 100 << 20]).unwrap(); // 100MB 零 → 压得很小
    let payload = encoder.finish().unwrap();

    let mut frame = vec![SIGNATURE | COMPRESSION_MASK];
    write_u32(&mut frame, payload.len());
    frame.extend_from_slice(&payload);

    let err = decode_frame(&frame).unwrap_err();
    assert!(
        err.contains("exceeds") || err.contains("zlib"),
        "decompression bomb must be capped with an error, got: {err}"
    );
}

// ============================================================
// 黄金向量(ZewSFS 互操作)
// ============================================================

/// `assets/sfs2x/golden.json` 的 manifest 结构。
#[derive(serde::Deserialize)]
struct GoldenManifest {
    cases: Vec<GoldenCase>,
}

#[derive(serde::Deserialize)]
struct GoldenCase {
    name: String,
    entries: Vec<GoldenEntry>,
}

#[derive(serde::Deserialize)]
struct GoldenEntry {
    key: String,
    #[serde(rename = "type")]
    type_code: u8,
    value: serde_json::Value,
}

/// 按 manifest 类型码把 JSON 值转成 Rust 端 [`Value`]。
fn build_value(type_code: u8, raw: &serde_json::Value) -> Value {
    match type_code {
        t::NULL => Value::Null,
        t::BOOL => Value::Bool(raw.as_bool().unwrap()),
        t::BYTE => Value::Byte(raw.as_i64().unwrap() as u8),
        t::SHORT => Value::Short(raw.as_i64().unwrap() as i16),
        t::INT => Value::Int(raw.as_i64().unwrap() as i32),
        t::LONG => Value::Long(raw.as_i64().unwrap()),
        t::FLOAT => Value::Float(raw.as_f64().unwrap() as f32),
        t::DOUBLE => Value::Double(raw.as_f64().unwrap()),
        t::UTF_STRING => Value::utf_string(raw.as_str().unwrap()),
        t::TEXT => Value::Text(raw.as_str().unwrap().to_string()),
        t::BYTE_ARRAY => {
            // manifest 里 BYTE_ARRAY 是 base64 字符串
            Value::ByteArray(crate::base64util::decode(raw.as_str().unwrap()).unwrap())
        }
        t::BOOL_ARRAY => Value::BoolArray(
            raw.as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_bool().unwrap())
                .collect(),
        ),
        t::SHORT_ARRAY => Value::ShortArray(
            raw.as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_i64().unwrap() as i16)
                .collect(),
        ),
        t::INT_ARRAY => Value::IntArray(
            raw.as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_i64().unwrap() as i32)
                .collect(),
        ),
        t::LONG_ARRAY => Value::LongArray(
            raw.as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_i64().unwrap())
                .collect(),
        ),
        t::FLOAT_ARRAY => Value::FloatArray(
            raw.as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_f64().unwrap() as f32)
                .collect(),
        ),
        t::DOUBLE_ARRAY => Value::DoubleArray(
            raw.as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_f64().unwrap())
                .collect(),
        ),
        t::UTF_STRING_ARRAY => Value::UtfStringArray(
            raw.as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap().to_string())
                .collect(),
        ),
        // 元素各带 {type, value}
        t::SFS_ARRAY => Value::SfsArray(
            raw.as_array()
                .unwrap()
                .iter()
                .map(|v| {
                    let obj = v.as_object().unwrap();
                    build_value(obj["type"].as_u64().unwrap() as u8, &obj["value"])
                })
                .collect(),
        ),
        // {"entries": [{key, type, value}...]}
        t::SFS_OBJECT => {
            let mut o = Object::new();
            for e in raw["entries"].as_array().unwrap() {
                o.put(
                    e["key"].as_str().unwrap().to_string(),
                    build_value(e["type"].as_u64().unwrap() as u8, &e["value"]),
                );
            }
            Value::SfsObject(o)
        }
        other => panic!("golden manifest carries unexpected type {other}"),
    }
}

/// ZewSFS 黄金向量:解码侧(它们的编码器 ↔ 我们的解码器)与编码侧
/// (我们的编码器 ↔ 它们的字节)双向断言。
#[test]
fn test_golden_vectors() {
    let manifest_path = assets_dir().join("golden.json");
    if !manifest_path.exists() {
        // 测试资产不入发布包(见 Cargo.toml exclude);缺失时跳过
        eprintln!("skip: assets/sfs2x missing (run testdata/golden_gen.py in go-utils first)");
        return;
    }
    let raw = std::fs::read_to_string(&manifest_path).unwrap();
    let manifest: GoldenManifest = serde_json::from_str(&raw).unwrap();
    assert!(!manifest.cases.is_empty(), "empty golden manifest");

    for tc in &manifest.cases {
        let bin = std::fs::read(assets_dir().join(format!("{}.bin", tc.name))).unwrap();

        let decoded = decode(&bin).unwrap_or_else(|e| panic!("Decode({}.bin): {e}", tc.name));

        // 重建对象(按 manifest 类型码),供字节级比对
        let mut rebuilt = Object::new();
        for e in &tc.entries {
            assert!(
                rebuilt.get(&e.key).is_none(),
                "duplicate key {:?} in manifest (sorted-insertion contract broken)",
                e.key
            );
            rebuilt.put(e.key.clone(), build_value(e.type_code, &e.value));
        }

        for e in &tc.entries {
            assert_eq!(
                decoded.get_type(&e.key),
                Some(e.type_code),
                "get_type({:?}) in case {}",
                e.key,
                tc.name
            );
            assert_eq!(
                decoded.get(&e.key),
                Some(&build_value(e.type_code, &e.value)),
                "key {:?} in case {}",
                e.key,
                tc.name
            );
        }

        // 字节级往返:重编码必须与 ZewSFS 原字节一致
        assert_eq!(
            rebuilt.encode(),
            bin,
            "re-encode mismatch in case {} (byte-faithful encode required)",
            tc.name
        );
    }
}

/// Go FuzzDecodeFrame 语料种子(测试语料形态,非正式 fuzz 目标)。
#[test]
fn test_fuzz_corpus_seeds_never_panic() {
    // go test fuzz v1 语料的十六进制形态种子
    let seeds: &[&[u8]] = &[
        b"\x8d00",
        &[0x80, 0x00, 0x02, 0x12, 0x00],
        &[0x80, 0x00, 0x01],
        &[0x80, 0x08, 0x00, 0x00, 0x00, 0x01, 0x12],
    ];
    for seed in seeds {
        let _ = decode_frame(seed);
        let _ = decode(seed);
    }
}
