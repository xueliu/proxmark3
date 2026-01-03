# Command

## Explore file system (EF/DF scanner)

```
script run fmcos_cli.py -c explore
```
cmd_explore 命令重构完成！

新的 explore 命令功能更强大，支持两种模式和自定义范围。

支持的参数：

--mode (ef 或 df)：指定扫描模式。
EF Mode (默认): 扫描 0000-0020 (可配置)
DF Mode: 扫描 DF01-DF10 (可配置)
--start, -S: 起始文件 ID (Hex)。
--end, -E: 结束文件 ID (Hex)。
使用示例：

扫描 EF (默认范围 0000-0020)
```
script run fmcos_cli -c explore
```
扫描 DF (默认范围 DF01-DF10)
```
script run fmcos_cli -c explore --mode df
```
自定义 EF 范围 (例如 0010-0030)
```
script run fmcos_cli -c explore --start 0010 --end 0030
```
在特定 DF 下扫描 (例如在 3F01 下)
```
script run fmcos_cli -c explore -f 3F01
```
扫描结果将显示文件类型（DF, Binary EF, Record EF, Key File）以及 FCI 信息概要。

## write_key

write_key 命令已重构支持 FMCOS 7.12 规范！

支持以下功能：

添加密钥 (默认模式)：使用 P1=01。
修改密钥：使用 --modify 参数，并支持通过 --key-type 指定密钥类型（如 39, 3A, 30 等）。
智能类型推断：如果修改模式下未指定类型，尝试从数据中推断。
会话保持：支持 --keep 和 --no-select。
按照博客流程重建环境的建议：

第一步：在 MF 下建立 3F01 应用目录

bash
# 这一步您之前好像已经做过了
script run fmcos_cli -c create -f 3F01 -d 380800F0F095FFFF1122334455 --keep
第二步：在 3F01 下创建密钥文件

bash
# 1. 选择 3F01 并保持场
script run fmcos_cli -c select -f 3F01 --no-select --keep
# 2. 创建密钥文件（ID=0000）
# 数据：3F(类型) 01(空间高) 8F(空间低) 95(DF) F0(权限) FF FF
# 注意：博客的空间是 018F，比默认值大
script run fmcos_cli -c create -f 0000 -d 3F018F95F0FFFF --no-select --keep
第三步：添加外部认证密钥 (Key 00)

bash
# 数据：39(ExtAuth) F0(Use) F0(Mod) AA(State) FF(Err) ...Key...
# 这里使用全 F 密钥进行演示，您可以保持博客的 1122...88
script run fmcos_cli -c write_key -k 00 -d 39F0F0AAFFFFFFFFFFFFFFFF --no-select --keep --debug
第四步：添加其他密钥 按照博客中的数据，只需更换 -d 参数即可。无需添加 --modify，因为这些都是新增密钥。

请尝试在 3F01 目录下执行这些步骤。此时 no-select 和 keep 配合应该能保持场和 DF 上下文。