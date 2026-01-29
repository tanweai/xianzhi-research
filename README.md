# 🔐 安全研究元思考方法论

> 从先知社区 5600+ 篇安全文档中提炼的漏洞挖掘核心思维框架

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## 📖 概述

这是一个 **Claude Code Skill**，为安全研究人员提供系统化的漏洞挖掘方法论指导。不同于具体的漏洞利用代码，本项目聚焦于**元认知层面**——如何思考、如何分析、如何构建攻击路径。

## 🧠 核心思维模型

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        安全研究思维金字塔                                │
├─────────────────────────────────────────────────────────────────────────┤
│  L4: 防御反推    ← 从补丁/过滤规则/安全机制反推绕过点                    │
│  L3: 边界探索    ← 在已知攻击面上寻找corner case                        │
│  L2: 假设验证    ← 构建推理链条，逐步验证假设                           │
│  L1: 攻击面识别  ← 寻找数据与指令不分离的接口                           │
└─────────────────────────────────────────────────────────────────────────┘
```

## 🎯 跨领域核心公式

| 领域 | 核心公式 | 关键洞察 |
|------|----------|----------|
| **通用** | 漏洞 = 边界失控 + 状态不一致 + 信任假设违背 | 所有漏洞的本质 |
| **代码审计** | 漏洞 = Source可达Sink && 无有效Sanitizer | 污点传播分析 |
| **二进制** | 利用 = 信息泄露 + 原语构造 + 控制流劫持 | 原语组合与放大 |
| **域渗透** | 攻击 = 信任链逐级瓦解 | 委派错误=整域沦陷 |

## 📚 模块索引

| 模块 | 文件 | 核心内容 |
|------|------|----------|
| **Web注入** | [web-injection.md](references/web-injection.md) | SQL/XSS/SSTI、WAF绕过策略树、语义差异利用 |
| **二进制安全** | [binary-exploitation.md](references/binary-exploitation.md) | ROP谱系、House of系列、glibc版本利用 |
| **域渗透** | [domain-pentest.md](references/domain-pentest.md) | Kerberos攻击、委派利用、横向移动 |
| **逆向分析** | [reverse-engineering.md](references/reverse-engineering.md) | VM对抗、反混淆、沙箱绕过 |
| **Fuzzing** | [fuzzing.md](references/fuzzing.md) | 目标选择、覆盖率驱动、变异策略 |
| **提权/绕过** | [privilege-bypass.md](references/privilege-bypass.md) | 免杀技术、EDR绕过、权限提升 |
| **RCE与持久化** | [rce-persistence.md](references/rce-persistence.md) | 后门技术、持久化方法 |
| **红队/CTF** | [redteam-ctf.md](references/redteam-ctf.md) | 完整攻击链、云安全 |
| **案例索引** | [case-index.md](references/case-index.md) | 按CVE/技术分类的真实案例 |

## 🚀 使用方法

### 作为 Claude Code Skill

1. 将本仓库克隆到 Claude Code 的 skills 目录：
   ```bash
   git clone https://github.com/tanweai/xianzhi-research.git ~/.claudeg/skills/vuln-research
   ```

2. 在 Claude Code 中使用：
   ```
   /vuln-research 如何审计一套Spring Boot代码
   /vuln-research Java反序列化Gadget链构造思路
   /vuln-research 域渗透中的Kerberos攻击路径
   ```

### 作为独立知识库

直接阅读各模块的 Markdown 文档，获取对应领域的方法论指导。

## 🔑 元思考原则

1. **假设-验证循环** — 所有安全研究都遵循：假设 → 测试 → 迭代优化
2. **边界条件思维** — Corner case 是所有漏洞类型的共同温床
3. **防御反推** — 从已知防御措施反推攻击路径是高效的研究策略
4. **链式思维** — 单个漏洞价值有限，漏洞链才能完成完整攻击
5. **版本敏感** — 同一漏洞点在不同版本需要不同利用方法
6. **语义差异** — 不同组件对同一输入的解析差异是绕过的核心

## 📊 数据来源

- 先知社区 5600+ 篇安全技术文章
- 公开 CVE 漏洞分析报告
- 红队实战经验总结
- CTF 竞赛 Writeup 提炼

## ⚠️ 免责声明

本项目仅供安全研究和教育目的使用。使用者应遵守当地法律法规，在获得授权的情况下进行安全测试。作者不对任何滥用行为负责。

## 📄 License

MIT License

---

**贡献者**: 欢迎提交 Issue 和 PR 来完善方法论内容。
