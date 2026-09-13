# unifont_cjk.bin

GNU Unifont 16px 位图字体子集,用于验证码模块的字符渲染
(ASCII 半宽字形 + CJK 统一表意文字区段 U+4E00–U+9FFF)。

- 来源: `unifont-16.0.04.hex` (http://unifoundry.com/pub/unifont/)
- 许可: GNU Unifont 双许可 —— SIL Open Font License 1.1 或
  GPLv2+ 附字体嵌入例外,二者任选。允许再分发与嵌入。
- 格式: 小端 `u32` 字形数量,随后每字形 `u32` 码点 + 32 字节位图
  (16 行 × 2 字节,半宽 ASCII 字形补零至 16 宽,MSB 在左侧)。

重新生成:

```bash
curl -sL -o unifont.hex.gz \
  "http://unifoundry.com/pub/unifont/unifont-16.0.04/font-builds/unifont-16.0.04.hex.gz"
gunzip unifont.hex.gz
python gen_unifont.py unifont.hex unifont_cjk.bin
```
