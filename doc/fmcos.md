# FMCOS 2.0 CLI 使用文档 (Lua版)

`hf_fmcos` 是一个基于 Lua 的 Proxmark3 客户端脚本，专为复旦微电子 FM1208 CPU 卡 (FMCOS 2.0) 设计。它提供了类似于 NetExec 的交互式命令行体验，支持文件管理、密钥认证、二进制/记录文件读写等功能。

## 基本用法

在 Proxmark3 客户端中运行：

```bash
script run hf_fmcos <command> [options]
```

查看全局帮助（列出所有命令）：
```bash
script run hf_fmcos
```

查看特定命令帮助：
```bash
script run hf_fmcos <command> --help
```

---

## 常用命令详解

### 1. select (选择文件)
选择一个文件 (MF/DF/EF) 从而进入其目录或上下文。

**用法**:
- 选择 FID (文件ID): `select <fid>`
- 选择应用名 (AID): `select -n <name>`

**选项**:
- `-s <fid>`: (通用选项) 在执行操作前先选择父目录 (通常用于其他命令，select 本身就是选择)。

**示例**:
```bash
# 选择主目录 (MF 3F00)
script run hf_fmcos select 3F00

# 选择 DF 3F01
script run hf_fmcos select 3F01

# 通过应用名选择 (1PAY.SYS.DDF01)
script run hf_fmcos select -n 315041592E5359532E4444463031
```

### 2. create_file (创建文件)
在当前目录下创建子目录 (DF) 或基本文件 (EF)。

**用法**: `create_file --type <type> [args] [options]`

**支持类型 (--type)**:
- **df**: 目录。参数 `<fid> <space> [name]`
- **binary**: 二进制文件。参数 `<fid> <size>`
- **fixed**: 定长记录文件。参数 `<fid> <rec_len> <rec_count>` (SFI 默认为 01)
- **cyclic**: 循环记录文件。参数同上。
- **key**: 密钥文件。参数 `<slots>` (容量=slots*17)

**选项**:
- `--perm <hex>`: 5字节权限控制字 (默认 FFFFFFFFFF)
- `--sfi <sfi>`: 指定 SFI (仅限记录文件)
- `-s <fid>`: 先选择父目录
- `-a <kid> -k <key>`: 进行外部认证 (创建文件通常需要认证)

**示例**:
```bash
# 创建 DF 3F01，空间 08，权限 FFFFFFFFFF
script run hf_fmcos create_file --type df 3F01 08 --perm FFFFFFFFFF

# 创建二进制 EF 0005，大小 32字节
script run hf_fmcos create_file --type binary 0005 32
```

### 3. read_binary / update_binary (二进制读写)
对 Binary EF 进行读写操作。

**用法**: 
- 读: `read_binary <offset> <len>`
- 写: `update_binary <offset> <data>`

**示例**:
```bash
# 从偏移 0 读取 16 字节
script run hf_fmcos read_binary 0005 0 16

# 向偏移 0 写入数据
script run hf_fmcos update_binary 0005 0 11223344
```

### 4. read_record / update_record (记录读写)
对 Record EF 进行读写操作。

**用法**:
- 读: `read_record <rec_num> [len]`
- 写: `update_record <rec_num> <data>`

**注意**: 若未指定 `len`，默认尝试读取该记录的全长 (Le=00/256)。
**SFI支持**: 可使用 `--sfi <id>` 强制使用 SFI 寻址模式。

**示例**:
```bash
# 读取第 1 条记录
script run hf_fmcos read_record 1

# 读取第 1 条记录 (指定长度 10 字节)
script run hf_fmcos read_record 1 10

# 更新第 1 条记录
script run hf_fmcos update_record 1 11223344
```

### 5. ext_auth (外部认证)
使用密钥进行外部认证以获取权限。

**用法**: `ext_auth <kid> <key>` 或者 `ext_auth -a <kid> -k <key>`

**参数**:
- `<kid>`: 密钥ID (如 00 代表 Master Key)
- `<key>`: 密钥值 (16进制，DES/3DES)

**示例**:
```bash
# 使用 Key 00 (默认主密钥) 认证
script run hf_fmcos ext_auth 00 FFFFFFFFFFFFFFFF
```

### 6. verify (PIN 校验)
校验 PIN 码 (用户口令)。

**用法**: `verify <kid> --pin <string>`

**参数**:
- `<kid>`: PIN 的 ID (通常是 01, 02 等)
- `--pin`: ASCII 字符串 PIN

**示例**:
```bash
# 校验 PIN (ID 01, 值为 "123456")
script run hf_fmcos verify 01 --pin 123456
```

### 7. write_key (写入/更新密钥)
创建或更新 Key 文件中的密钥记录。

**用法**: `write_key <kid> [data] [options]`

**选项**:
- `--type <type>`: 密钥类型 (pin, ext_auth, master)
- `--pin <str>`: 如果是 PIN，指定值
- `--key <hex>`: 如果是密钥，指定 Hex 值
- `--level <hex>`: 安全等级 (默认 0F)

**示例**:
```bash
# 写入 Key 00 (Master Key)
script run hf_fmcos write_key 00 --type ext_auth --key 1122334455667788

# 写入 Key 01 (PIN)
script run hf_fmcos write_key 01 --type pin --pin "888888"
```

### 8. explore (文件扫描)
扫描卡片文件系统的便利工具。它通过枚举 FID 来探测存在的 DF 和 EF。

**用法**: `explore [options]`

**选项**:
- `--mode <mode>`: 扫描模式。
  - `ef` (默认): 扫描当前目录下的 EF (PID范围 0000-0020).
  - `df`: 扫描当前目录下的子 DF (FID范围 DF01-DF10).
- `--start <hex>`: 指定起始 FID (如 `0000`).
- `--end <hex>`: 指定结束 FID (如 `00FF`).
- `-s <fid>`: 先选择某个父目录，再扫描其下内容。

**示例**:
```bash
# 扫描当前目录下的标准 EF (0000-0020)
script run hf_fmcos explore

# 扫描 3F00 下的 DF 应用 (DF01-DF10)
script run hf_fmcos explore -s 3F00 --mode df

# 自定义范围扫描 (搜索可能的隐藏文件)
script run hf_fmcos explore --start 0000 --end 00FF
```

### 9. erase_df (擦除目录)
擦除当前选择的 Directory File (DF) 及其下所有文件。**危险操作，请谨慎使用。**
执行后，卡片上下文会自动回到 MF (3F00)。

**用法**: `erase_df`

**注意**: 通常需要主目录的擦除权限 (擦除是父目录的管理操作)。

**示例**:
```bash
# 选择并擦除 3F01
script run hf_fmcos select 3F01
script run hf_fmcos erase_df
```

### 10. balance (查询余额)
用于电子钱包 (EP) 或存折 (ED) 应用，查询余额。

**用法**: `balance [type]`

**参数**:
- `type`: 钱包类型。`01` = 电子存折 (ED), `02` = 电子钱包 (EP, 默认)。

**示例**:
```bash
# 查询电子钱包余额
script run hf_fmcos balance

# 查询电子存折余额
script run hf_fmcos balance 01
```

### 11. challenge (获取随机数)
向卡片请求随机数 (Get Challenge)，通常用于测试通信或作为安全过程的一部分。

**用法**: `challenge [len]`

**参数**:
- `len`: 请求长度 (默认 4 或 8 字节).

**示例**:
```bash
script run hf_fmcos challenge 8
```

### 12. apdu (原生指令)
发送原始 APDU Hex 字符串。用于调试或执行未封装的命令。

**用法**: `apdu <hex_data>`

**示例**:
```bash
# 发送 Select 3F00 指令 (00A40000023F00)
script run hf_fmcos apdu 00A40000023F00
```

### 13. run (脚本执行)
执行包含一系列 `hf_fmcos` 命令的脚本文件。对于批量初始化或测试非常有用。

**用法**: `run -f <filename>`

**脚本文件格式**:
- 每行一条命令 (不含 `script run hf_fmcos` 前缀)。
- `#` 开头为注释。
- 支持空行。

**示例文件 (setup.txt)**:
```text
# 初始化脚本
select 3F00
ext_auth 00 FFFFFFFFFFFFFFFF
create_file --type df 3F01 08
```

**执行**:
```bash
script run hf_fmcos run -f setup.txt
```

---

## 开发环境搭建 (PBOC 示例)

以下是一个完整的初始化脚本示例，演示如何创建一个类似 PBOC 的环境：创建目录、创建密钥文件、写入主密钥和 PIN，并进行认证。

您可以将以下命令保存为 `.txt` 文件并使用 `script run hf_fmcos run -f <file>` 执行，或者逐条运行。

### 第1步：创建 DF (3F01)
在 MF (3F00) 下创建一个名为 3F01 的目录，并赋予权限。因为是新卡，我们首先需要用 MF 的 Key 00 认证。

```bash
# 选择 MF (3F00), 认证 Key 00, 创建 DF 3F01
script run hf_fmcos create_file --type df -s 3F00 -a 00 -k FFFFFFFFFFFFFFFF 3F01 08
```

### 第2步：创建密钥文件
在刚创建的 3F01 下创建 Key EF (FID 0000 默认)。

```bash
# 在 3F01 下创建 Key File (容量为 1 个该类型大小，通常给足够 slots)
script run hf_fmcos create_file --type key 1 --perm 8F95F0FFFF -s 3F01
```

### 第3步：写入密钥
向密钥文件写入 Master Key (Key 00) 和 PIN (Key 01)。

```bash
# 写入主密钥 Key 00 (External Auth)
script run hf_fmcos write_key -s 3F01 00 --type ext_auth --key 1122334455667788

# 写入用户 PIN Key 01 (Pin)
script run hf_fmcos write_key -s 3F01 01 --type pin --pin "123456"
```

### 第4步：验证权限
现在可以使用新密钥进行认证。

**验证主密钥**:
```bash
script run hf_fmcos ext_auth -s 3F01 -a 00 -k 1122334455667788
# 预期结果: 9000 OK
```

**验证 PIN**:
```bash
script run hf_fmcos verify -s 3F01 01 --pin "123456"
# 预期结果: 9000 OK (安全等级提升)
```
