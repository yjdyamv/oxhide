# VeraCrypt Rust Implementation Guide

完整的VeraCrypt Rust重写实现指南，包含所有模块的设计和实现细节。

## 项目概述

本项目使用Rust重写VeraCrypt，保持100%格式兼容性。

## 架构

- **vcrypt-core**: 核心加密库（密码算法、哈希、KDF、XTS模式）
- **vcrypt-format**: 卷格式处理（头部解析、加密/解密）
- **vcrypt-volume**: 卷操作（I/O、挂载）
- **vcrypt-cli**: 命令行界面

## 关键实现要点

### 密码算法
- AES-256、Serpent、Twofish（使用现有crate）
- Camellia、Kuznyechik（需要从C移植）
- 支持级联加密

### XTS模式
- 512字节扇区加密
- Galois域乘法用于tweak更新
- 与VeraCrypt完全兼容

### 卷头格式
- 64KB总大小，512字节有效数据
- Magic: 0x56455241 ("VERA")
- 64字节盐 + 加密元数据

## 实现状态

详见 `.claude/plans/veracrypt-rust-rewrite.md` 查看完整计划。
