# VeraCrypt 源码架构参考

> 分析来源: `C:\Users\yuan\Downloads\VeraCrypt-master\` (版本 1.26.29)
> 用途: Rust 重写项目的长期参考文档

---

## 1. 高层架构 (4层模型)

```
┌─────────────────────────────────────────────────────┐
│ Layer 4: UI   │ Main/ (wxWidgets GUI + CLI)        │
│               │ Mount/ Format/ Setup/ (Win32 GUI)   │
├─────────────────────────────────────────────────────┤
│ Layer 3: 平台  │ Platform/ (跨平台抽象)              │
│               │ Common/ (共享C代码, XTS, PKCS5)      │
│               │ Driver/ (Windows内核驱动 + FUSE)     │
├─────────────────────────────────────────────────────┤
│ Layer 2: 核心  │ Core/ (卷创建/挂载, RNG, 线程池)    │
│               │ Volume/ (卷格式, 头, 密码, KDF)      │
├─────────────────────────────────────────────────────┤
│ Layer 1: 加密  │ Crypto/ (密码原语, 哈希, Argon2)    │
└─────────────────────────────────────────────────────┘
     Boot/ (独立引导加载程序, 有自己的加密子集)
```

**关键设计决策:**
- C 用于底层 (驱动, 引导, Win32 GUI) + 加密原语 (SIMD汇编)
- C++ 用于中间件 (跨平台核心, wxWidgets GUI)
- 驱动层和用户层有**两套并行**的 XTS / PBKDF2 实现

---

## 2. 源目录清单 (21个目录)

| 目录 | 语言 | 用途 |
|------|------|------|
| `src/Crypto/` | C+ASM | 加密原语 (AES, Serpent, Twofish, Camellia, Kuznyechik, SHA-*, BLAKE2s, Whirlpool, Streebog, Argon2, ChaCha20) |
| `src/Common/` | C | 共享代码 (XTS, PKCS5, 缓存, 密钥文件, GfMul, CRC, 压缩) |
| `src/Volume/` | C++ | 卷管理 (Volume, VolumeHeader, VolumeLayout, EncryptionMode, Cipher, Hash, Pkcs5Kdf) |
| `src/Core/` | C++ | 核心中间件 (VolumeCreator, FatFormatter, RNG, HostDevice, 加密线程池) |
| `src/Core/Unix/` | C++ | Unix核心 (CoreService, Linux/FreeBSD/MacOSX后端) |
| `src/Platform/` | C++ | 平台抽象 (File, Memory, Thread, Mutex, Serializer) |
| `src/Platform/Unix/` | C++ | Unix平台后端 |
| `src/Main/` | C++ | 主应用程序 + wxWidgets GUI 所有对话框 |
| `src/Main/Unix/` | C++ | Unix入口点 `Main.cpp` |
| `src/Driver/` | C | Windows内核驱动 (Ntdriver, Ntvol, DriveFilter) |
| `src/Driver/Fuse/` | C++ | Linux/macOS FUSE 服务 |
| `src/Mount/` | C | Windows挂载GUI (Mount.c, Favorites.c) |
| `src/Format/` | C | Windows格式化GUI (Tcformat.c) |
| `src/Setup/` | C | Windows安装程序 |
| `src/ExpandVolume/` | C++ | Windows卷扩展工具 |
| `src/Boot/Windows/` | C++ | Windows MBR引导加载程序 |
| `src/Boot/EFI/` | 预编译 | UEFI引导加载程序 (外部DCS仓库) |
| `src/FormatDLL/` | C++ | Windows格式化SDK |
| `src/SetupDLL/` | C++ | Windows安装DLL |
| `src/COMReg/` | C++ | Windows COM注册 |
| `src/PKCS11/` | 头文件 | PKCS#11 加密令牌接口 |

---

## 3. 加密原语

### 3.1 密码算法

| 算法 | 源文件 | 密钥函数 | 块/密钥大小 | 密钥调度大小 |
|------|--------|----------|-------------|-------------|
| **AES** | `Aes.h`, `Aescrypt.c`, `Aeskey.c`, `Aes_hw_cpu.c` (AES-NI), `Aes_hw_armv8.c` | `aes_encrypt_key256()`, `aes_encrypt()` | 16/32 | ~240B |
| **Serpent** | `Serpent.c`, `SerpentFast.c`, `SerpentFast_simd.cpp` | `serpent_set_key()`, `serpent_encrypt()` | 16/32 | 560B |
| **Twofish** | `Twofish.c`, `Twofish_x64.S` | `twofish_set_key()`, `twofish_encrypt()` | 16/32 | ~4256B |
| **Camellia** | `Camellia.c`, `CamelliaSmall.c`, `Camellia_aesni_x64.S` | `camellia_set_key()`, `camellia_encrypt()` | 16/32 | 272B |
| **Kuznyechik** | `kuznyechik.c`, `kuznyechik_simd.c` | `kuznyechik_set_key()`, `kuznyechik_encrypt_block()` | 16/32 | ~320B |

**密码ID枚举** (`src/Common/Crypto.h`):
```
NONE=0, AES=1, SERPENT=2, TWOFISH=3, CAMELLIA=4, KUZNYECHIK=5
```

**级联密码** (16种, 定义于 `src/Volume/EncryptionAlgorithm.h`):
- 单密码: AES, Serpent, Twofish, Camellia, Kuznyechik
- 2级联: AES-Twofish, AES-Twofish-Serpent, Serpent-AES, Serpent-Twofish-AES, Twofish-Serpent
- 3级联: AES(Twofish(Serpent)) 等

### 3.2 哈希函数

| 算法 | 源文件 | 输出大小 | PRF ID |
|------|--------|----------|--------|
| **SHA-256** | `Sha2.c`, `sha256_avx2_x64.asm`, `Sha2Intel.c` | 32B | 3 |
| **SHA-512** | `Sha2.c`, `sha512_avx2_x64.asm` | 64B | 1 |
| **BLAKE2s** | `blake2s.c`, `blake2s_SSE41.c` | 32B | 5 |
| **Whirlpool** | `Whirlpool.c` | 64B | 2 |
| **Streebog** | `Streebog.c` (GOST) | 64B | 6 |
| **Argon2** (间接) | `Argon2/src/ref.c` | — | 7 |

**PRF ID枚举** (`src/Common/Crypto.h`):
```
SHA512=1, WHIRLPOOL=2, SHA256=3, BLAKE2S=4, STREEBOG=5, ARGON2=6
```

### 3.3 密钥派生

**C层 PBKDF2** (`src/Common/Pkcs5.c`):

| PRF | HMAC函数 | derive函数 |
|-----|----------|------------|
| SHA-256 | `hmac_sha256()` | `derive_key_sha256()` |
| SHA-512 | `hmac_sha512()` | `derive_key_sha512()` |
| Whirlpool | `hmac_whirlpool()` | `derive_key_whirlpool()` |
| BLAKE2s | `hmac_blake2s()` | `derive_key_blake2s()` |
| Streebog | `hmac_streebog()` | `derive_key_streebog()` |

**Argon2** (`src/Crypto/Argon2/`):
- 类型: `Argon2_id`
- `argon2_hash(t_cost, m_cost, parallelism, pwd, salt, hash, type)`

**C++ KDF类** (`src/Volume/Pkcs5Kdf.h`): 9个子类 (Sha512/Sha256/Blake2s/Whirlpool/Streebog/Argon2 + Boot变体)

**迭代次数**: 默认 500,000 (Boot: 200,000)

### 3.4 XTS 模式 (双重实现)

| 层 | 文件 | 函数 |
|----|------|------|
| **C (驱动/引导)** | `src/Common/Xts.c` | `EncryptBufferXTS()`, `DecryptBufferXTS()` |
| **C++ (用户层)** | `src/Volume/EncryptionModeXTS.cpp` | `EncryptionModeXTS::Encrypt()`, `Decrypt()` |

**关键常量:** `BYTES_PER_XTS_BLOCK=16`, `ENCRYPTION_DATA_UNIT_SIZE=512`
**GF(2^128)** 多项式: x^128 + x^7 + x^2 + x + 1 (乘数常量 135)

### 3.5 随机数生成 (三层)

| 层 | 文件 | 用途 |
|----|------|------|
| **主熵池** | `src/Common/Random.c` | 320字节池, Win32钩子/周期性轮询 |
| **ChaCha20 RNG** | `src/Crypto/chachaRng.c` | 内核模式确定性CSPRNG |
| **CPU RNG** | `src/Crypto/rdrand.c`, `jitterentropy-base.c` | RDRAND/RDSEED + CPU时序抖动 |

---

## 4. 卷格式规范

### 4.1 卷头 v5 (当前版本)

```
Total size:  65536 (64 KiB)
Effective:   512 bytes
Group:       2×64KB = 128 KiB (主+备份)
Layout:      [主头 64KB][备份头 64KB][隐藏卷头(可选)]
```

### 4.2 字节布局 (来源: `src/Common/Volumes.c`)

| 偏移 | 长度 | 字段 | 说明 |
|------|------|------|------|
| 0 | 64 | Salt | 未加密 |
| **加密区域** | | | |
| 64 | 4 | Magic | `0x56455241` ("VERA") |
| 68 | 2 | HeaderVersion | 0x0005 |
| 70 | 2 | RequiredVersion | 最低版本 |
| 72 | 4 | KeyAreaCRC | 字节 256-511 CRC-32 |
| 76 | 16 | Reserved | 零 |
| 92 | 8 | HiddenVolumeSize | 0=普通卷 |
| 100 | 8 | VolumeSize | 总字节数 |
| 108 | 8 | EncryptedAreaStart | 数据起始偏移 |
| 116 | 8 | EncryptedAreaLength | 数据长度 |
| 124 | 4 | Flags | 0x1=系统加密, 0x2=原地加密 |
| 128 | 4 | SectorSize | 通常512 |
| 132 | 120 | Reserved | 零 |
| 252 | 4 | HeaderCRC | 字节 64-251 CRC-32 |
| 256 | 256 | MasterKeydata | 级联主密钥+次密钥 |

### 4.3 关键常量

| 常量 | 值 | 来源 |
|------|-----|------|
| `TC_HEADER_MAGIC_NUMBER` | `0x56455241` | `Volumes.h` |
| `VOLUME_HEADER_VERSION` | `0x0005` | `Volumes.h` |
| `TC_VOLUME_HEADER_SIZE` | 65536 | `Volumes.h` |
| `TC_VOLUME_HEADER_EFFECTIVE_SIZE` | 512 | `Volumes.h` |
| `PKCS5_SALT_SIZE` | 64 | `Crypto.h` |
| `MASTER_KEYDATA_SIZE` | 256 | `Crypto.h` |
| `ENCRYPTION_DATA_UNIT_SIZE` | 512 | `Crypto.h` |

### 4.4 挂载流程

```
1. 读取 64KB 头部 → 2. 提取 64字节 Salt
3. 试遍所有 PRF (SHA-512→Whirlpool→SHA-256→BLAKE2s→Streebog→Argon2)
4. 试遍所有密码组合 (单密码+级联) → 5. PBKDF2 派生头部密钥
6. XTS 解密加密区域 → 7. 验证 Magic="VERA" → 8. 验证 CRC
9. 提取主密钥 → 10. 初始化 XTS → 11. 扇区 I/O
```

---

## 5. Rust 实现对照表

| VeraCrypt 组件 | Rust 实现 | 状态 |
|----------------|-----------|------|
| **密码算法** | | |
| AES-256 | `vcrypt_core::AesCipher` | ✅ |
| Serpent | `vcrypt_core::SerpentCipher` | ✅ |
| Twofish | `vcrypt_core::TwofishCipher` | ✅ |
| Camellia-256 | `vcrypt_core::CamelliaCipher` | ✅ |
| Kuznyechik | `vcrypt_core::KuznyechikCipher` | ✅ |
| 级联密码 (5种) | `vcrypt_core::CascadeCipher` | ✅ |
| **哈希函数** | | |
| SHA-256 | `vcrypt_core::Sha256Hash` | ✅ |
| SHA-512 | `vcrypt_core::Sha512Hash` | ✅ |
| BLAKE2s-256 | `vcrypt_core::Blake2sHash` | ✅ |
| Whirlpool | `vcrypt_core::WhirlpoolHash` | ✅ `whirlpool` v0.10 (RustCrypto, 5.89M) |
| Streebog | `vcrypt_core::StreebogHash` | ✅ `streebog` v0.11 (RustCrypto, LE字序) |
| **KDF** | | |
| PBKDF2-HMAC-SHA-256 | `vcrypt_core::Pbkdf2Sha256` | ✅ |
| PBKDF2-HMAC-SHA-512 | `vcrypt_core::Pbkdf2Sha512` | ✅ |
| PBKDF2-HMAC-BLAKE2s | `vcrypt_core::Pbkdf2Blake2s` | ⚠️ SHA-256回退 |
| Argon2id | `vcrypt_core::Argon2idKdf` | ✅ |
| **XTS** | `vcrypt_core::XtsMode` | ⚠️ 缺CTS |
| **卷格式** | | |
| 卷头结构 | `vcrypt_format::VolumeHeader` | ✅ |
| 头序列化/反序列化 | `vcrypt_format::ser/deser` | ✅ |
| 头加密/解密 | — | ❌ |
| 密钥文件 | — | ❌ |
| **卷操作** | | |
| VolumeConfig | `vcrypt_volume::VolumeConfig` | ✅ |
| Volume | `vcrypt_volume::Volume` | 🔧 框架 |
| 扇区I/O | — | ❌ |
| 卷创建 | — | ❌ |
| **CLI** | `vcrypt-cli` (create/info/test) | 🔧 基础 |
| **FUSE** | — | ❌ |
| **RNG** | — | ❌ |

✅=完成 ⚠️=部分 🔧=框架 ❌=未开始

---

## 6. Whirlpool & Streebog 移植 (已完成)

### Whirlpool — ✅ 使用 `whirlpool` crate v0.10
- Crate: [whirlpool](https://crates.io/crates/whirlpool) (RustCrypto/Hashes, 5.89M downloads)
- 特质: 实现 `digest::Digest` trait, `no_std` 兼容
- `asm` 特性可用 (x86/x86-64 汇编加速)
- VeraCrypt源: `src/Crypto/Whirlpool.c` (~600行C, 不再需要移植)

### Streebog — ✅ 使用 `streebog` crate v0.11
- Crate: [streebog](https://crates.io/crates/streebog) (RustCrypto/Hashes, 380K downloads)
- 特质: 实现 `digest::Digest` trait, `no_std` 兼容
- v0.11 相比 v0.10: 修复部分字节序问题 (256-bit已正确, 512-bit仍为LE字序)
- 注意: 输出值与GOST大端标准有字序差异, 但VeraCrypt自身使用LE字序解析Streebog输出
- VeraCrypt源: `src/Crypto/Streebog.c` (~400行C, 不再需要移植)
