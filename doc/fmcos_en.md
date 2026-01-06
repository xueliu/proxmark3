# FMCOS 2.0 CLI Documentation (Lua Version)

`hf_fmcos` is a Lua-based Proxmark3 client script designed for Fudan Microelectronics FM1208 CPU cards (FMCOS 2.0). It provides a NetExec-style interactive command-line interface, supporting file management, key authentication, binary/record file operations, and more.

## Basic Usage

Run inside the Proxmark3 client:

```bash
script run hf_fmcos <command> [options]
```

View global help (list all commands):

```bash
script run hf_fmcos
```

View info for a specific command:

```bash
script run hf_fmcos <command> --help
```

---

## Command Reference

### 1. select (Select File)

Select a file (MF/DF/EF) to enter its directory or context.

**Usage**:

- Select by FID (File ID): `select <fid>`
- Select by Application Name (AID): `select -n <name>`

**Options**:

- `-s <fid>`: (Common Option) Select parent directory first before executing the command (note: `select` command itself changes context directly).

**Examples**:

```bash
# Select Master File (MF 3F00)
script run hf_fmcos select 3F00

# Select DF 3F01
script run hf_fmcos select 3F01

# Select by Application Name (1PAY.SYS.DDF01)
script run hf_fmcos select -n 315041592E5359532E4444463031
```

### 2. create_file (Create File)

Create a sub-directory (DF) or Elementary File (EF) in the current directory.

**Usage**: `create_file --type <type> [args] [options]`

**Supported Types (--type)**:

- **df**: Directory. Args: `<fid> <space> [name]`
- **binary**: Binary EF. Args: `<fid> <size>`
- **fixed**: Fixed Record EF. Args: `<fid> <rec_len> <rec_count>` (SFI defaults to 01)
- **cyclic**: Cyclic Record EF. Args: same as fixed.
- **key**: Key File. Args: `<slots>` (Capacity = slots * 17 bytes)

**Options**:

- `--perm <hex>`: 5-byte Permission Control Word (Default: FFFFFFFFFF)
- `--sfi <sfi>`: Specify Short File Identifier (Record files only)
- `-s <fid>`: Select parent directory first
- `-a <kid> -k <key>`: Perform External Authentication (usually required to create files)

**Examples**:

```bash
# Create DF 3F01, Space 08, Perms FFFFFFFFFF
script run hf_fmcos create_file --type df 3F01 08 --perm FFFFFFFFFF

# Create Binary EF 0005, Size 32 bytes
script run hf_fmcos create_file --type binary 0005 32
```

### 3. read_binary / update_binary (Binary Operations)

Read or Write to a Binary EF.

**Usage**:

- Read: `read_binary <offset> <len>`
- Write: `update_binary <offset> <data>`

**Examples**:

```bash
# Read 16 bytes from offset 0
script run hf_fmcos read_binary 0005 0 16

# Write data to offset 0
script run hf_fmcos update_binary 0005 0 11223344
```

### 4. read_record / update_record (Record Operations)

Read or Write to a Record EF.

**Usage**:

- Read: `read_record <rec_num> [len]`
- Write: `update_record <rec_num> <data>`

**Note**: If `len` is not specified, it attempts to read the full record length (Le=00/256).
**SFI Support**: Use `--sfi <id>` to force SFI addressing mode.

**Examples**:

```bash
# Read Record #1
script run hf_fmcos read_record 1

# Read Record #1 (Explicit length 10 bytes)
script run hf_fmcos read_record 1 10

# Update Record #1
script run hf_fmcos update_record 1 11223344
```

### 5. ext_auth (External Authentication)

Authenticate using a key to gain permissions.

**Usage**: `ext_auth <kid> <key>` or `ext_auth -a <kid> -k <key>`

**Arguments**:

- `<kid>`: Key ID (e.g., 00 for Master Key)
- `<key>`: Key Value (Hex, DES/3DES)

**Examples**:

```bash
# Authenticate with Key 00 (Default Master)
script run hf_fmcos ext_auth 00 FFFFFFFFFFFFFFFF
```

### 6. verify (PIN Verification)

Verify a User PIN.

**Usage**: `verify <kid> --pin <string>`

**Arguments**:

- `<kid>`: PIN ID (usually 01, 02...)
- `--pin`: ASCII String PIN

**Examples**:

```bash
# Verify PIN (ID 01, value "123456")
script run hf_fmcos verify 01 --pin 123456
```

### 7. write_key (Write/Update Key)

Create or Update a key record in the Key File.

**Usage**: `write_key <kid> [data] [options]`

**Options**:

- `--type <type>`: Key type (pin, ext_auth, master)
- `--pin <str>`: Specify PIN value (if type is pin)
- `--key <hex>`: Specify Key hex value (if type is key)
- `--level <hex>`: Security Level (Default: 0F)

**Examples**:

```bash
# Write Key 00 (Master Key)
script run hf_fmcos write_key 00 --type ext_auth --key 1122334455667788

# Write Key 01 (PIN)
script run hf_fmcos write_key 01 --type pin --pin "888888"
```

### 8. explore (File System Scanner)

A convenient tool to scan the card's file system by brute-forcing FIDs to detect DFs and EFs.

**Usage**: `explore [options]`

**Options**:

- `--mode <mode>`: Scan mode.
  - `ef` (Default): Scan for EFs in current directory (FID range 0000-0020).
  - `df`: Scan for sub-DFs in current directory (FID range DF01-DF10).
- `--start <hex>`: Specify Start FID (e.g. `0000`).
- `--end <hex>`: Specify End FID (e.g. `00FF`).
- `-s <fid>`: Select a parent directory first, then scan its contents.

**Examples**:

```bash
# Scan for standard EFs in current directory (0000-0020)
script run hf_fmcos explore

# Scan for DFs under 3F00 (DF01-DF10)
script run hf_fmcos explore -s 3F00 --mode df

# Custom range scan (Search for hidden files)
script run hf_fmcos explore --start 0000 --end 00FF
```

### 9. erase_df (Erase Directory)

Erase the currently selected Directory File (DF) and all its contents. **Dangerous operation, use with caution.**
After execution, files context resets to MF (3F00).

**Usage**: `erase_df`

**Note**: Typically requires erase permissions of the parent directory.

**Examples**:

```bash
# Select and Erase 3F01
script run hf_fmcos select 3F01
script run hf_fmcos erase_df
```

### 10. balance (Check Balance)

Used for Electronic Purse (EP) or Electronic Deposit (ED) applications to check balance.

**Usage**: `balance [type]`

**Arguments**:

- `type`: Wallet type. `01` = Electronic Deposit (ED), `02` = Electronic Purse (EP, Default).

**Examples**:

```bash
# Check Electronic Purse Balance
script run hf_fmcos balance

# Check Electronic Deposit Balance
script run hf_fmcos balance 01
```

### 11. challenge (Get Random)

Request a random challenge from the card (Get Challenge), typically used for comms testing or security flows.

**Usage**: `challenge [len]`

**Arguments**:

- `len`: Request length (Default 4 or 8 bytes).

**Examples**:

```bash
script run hf_fmcos challenge 8
```

### 12. apdu (Raw Command)

Send raw APDU Hex string. Useful for debugging or executing unrecognised commands.

**Usage**: `apdu <hex_data>`

**Examples**:

```bash
# Send Select 3F00 Command (00A40000023F00)
script run hf_fmcos apdu 00A40000023F00
```

### 13. run (Execute Script)

Execute a script file containing a sequence of `hf_fmcos` commands. Useful for batch initialization or testing.

**Usage**: `run -f <filename>`

**Script File Format**:

- One command per line (without `script run hf_fmcos` prefix).
- `#` for comments.
- Empty lines supported.

**Example File (setup.txt)**:

```text
# Initialization Script
select 3F00
ext_auth 00 FFFFFFFFFFFFFFFF
create_file --type df 3F01 08
```

**Execution**:

```bash
script run hf_fmcos run -f setup.txt
```

---

## Development Environment Setup (PBOC Example)

The following is a complete initialization script example demonstrating how to set up a PBOC-like environment: Creating a directory, creating a key file, writing Master Key and PIN, and authenticating.

You can save these commands to a `.txt` file and run with `script run hf_fmcos run -f <file>`, or run them one by one.

### Step 1: Create DF (3F01)

Create a directory named 3F01 under MF (3F00). Since it's a fresh card, authenticate with MF Key 00 first.

```bash
# Select MF (3F00), Auth Key 00, Create DF 3F01
script run hf_fmcos create_file --type df -s 3F00 -a 00 -k FFFFFFFFFFFFFFFF 3F01 08
```

### Step 2: Create Key File

Create a Key EF (FID 0000 by default) under the newly created 3F01.

```bash
# Create Key File under 3F01 (Capacity 1 slot for now, usually create more)
script run hf_fmcos create_file --type key 1 --perm 8F95F0FFFF -s 3F01
```

### Step 3: Write Keys

Write the Master Key (Key 00) and PIN (Key 01) into the key file.

```bash
# Write Master Key 00 (External Auth)
script run hf_fmcos write_key -s 3F01 00 --type ext_auth --key 1122334455667788

# Write User PIN 01 (Pin)
script run hf_fmcos write_key -s 3F01 01 --type pin --pin "123456"
```

### Step 4: Verify Permissions

Now you can authenticate using the new keys.

**Verify Master Key**:

```bash
script run hf_fmcos ext_auth -s 3F01 -a 00 -k 1122334455667788
# Expected: 9000 OK
```

**Verify PIN**:

```bash
script run hf_fmcos verify -s 3F01 01 --pin "123456"
# Expected: 9000 OK (Security Level upgraded)
```
