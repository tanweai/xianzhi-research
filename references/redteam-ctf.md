# 红队攻防/CTF方法论

## 红队攻防思维

### 完整攻击链

```
边界突破 → 权限提升 → 内网穿透 → 横向移动 → 域控攻击 → 权限维持
    ↓          ↓          ↓          ↓          ↓          ↓
 Web漏洞   Potato系    代理隧道    密码复用   Zerologon   黄金票据
 服务CVE   Mimikatz   Stowaway    PTH/PTT    krbtgt      持久化
```

### 各阶段核心技术

#### 阶段一：边界突破

| 入口类型 | 利用方式 | 工具/技术 |
|----------|----------|-----------|
| Web漏洞 | SQL注入写Shell、文件上传 | SQLMap、蚁剑 |
| 服务漏洞 | Redis未授权、CVE利用 | 备份文件写Shell |
| 社工钓鱼 | 宏文件、伪装程序 | Office宏、捆绑木马 |

#### 阶段二：权限提升

- Windows：Potato系列提权、PsExec提升至SYSTEM
- Linux：SUID、sudo配置、内核漏洞
- 密码抓取：Mimikatz抓取明文/Hash

#### 阶段三：内网穿透

| 技术 | 工具 | 特点 |
|------|------|------|
| HTTP隧道 | reGeorg、Neo-reGeorg | Web服务器做代理 |
| SOCKS代理 | EarthWorm、Stowaway | 多级代理 |
| DNS隧道 | dnscat2 | 隐蔽性高 |
| ICMP隧道 | pingtunnel | 绕过防火墙 |

#### 阶段四：横向移动

**核心洞察**："内网里的服务器账号密码有部分可能是相同的" —— 经验驱动的横向移动思维

| 凭据类型 | 攻击方式 |
|----------|----------|
| 明文密码 | PSExec、WMI、RDP |
| NTLM Hash | PTH (Pass-The-Hash) |
| Kerberos票据 | PTT (Pass-The-Ticket) |

#### 阶段五：域控攻击

- CVE-2020-1472 (ZeroLogon)：置空域控机器账户NTLM Hash
- CVE-2021-42287/42278：sAMAccountName欺骗
- 黄金票据：获取krbtgt的NTLM Hash制作永久后门

### 无CS/MSF场景的替代

```
问题：目标不出网，无法使用常规C2

替代方案：
├── 正向连接木马（目标不出网时）
├── certutil远程下载
├── 原生Windows工具利用（Living off the Land）
└── PowerShell Empire内存执行
```

---

## CTF解题思维

### 核心思维模式

| 阶段 | 思维要点 | 关键动作 |
|------|----------|----------|
| **信息识别** | 快速定位题目类型和考点 | 识别关键词、版本号、技术栈 |
| **攻击面枚举** | 穷举所有可能的攻击向量 | 目录扫描、源码泄露、已知漏洞 |
| **链式突破** | 多个小漏洞串联成完整攻击链 | SSRF→RCE、SQL注入→后台→上传 |
| **逆向验证** | 从结果反推过程 | 密文逆向、协议分析 |

### 分类解题方法论

#### Web方向

- **路径穿越**：`../../`构造访问非预期资源
- **编码绕过**：双重URL编码、Unicode编码
- **序列化攻击**：Phar反序列化、Fastjson
- **代码审计链**：源码泄露 → 路由分析 → 危险函数 → Payload

#### Crypto方向

| 攻击类型 | 关键技术 |
|----------|----------|
| **LCG攻击** | 已知输出恢复a、b、m参数 |
| **MT19937预测** | 收集624个输出，RandCrack预测 |
| **LFSR分析** | B-M算法恢复mask |
| **RSA攻击** | 小指数、共模、Wiener |

#### Pwn方向

- 栈溢出 → ROP → ret2libc/ret2syscall
- 堆利用 → tcache poisoning → 任意地址分配
- 格式化字符串 → 任意读写

---

## 云安全攻防

### 对象存储(S3/OBS)攻击面

```
1. Bucket暴力猜解（NoSuchBucket vs AccessDenied）
2. 对象遍历（ListBucket权限泄露）
3. ACL策略可写（Everyone写ACL）
4. 策略冲突（桶策略与桶ACL配置不一致）
```

**关键发现**：
- `--no-sign-request`参数可绕过某些认证检查
- X-Forwarded-For可绕过IP限制的ListBucket
- Referer头部Fuzzing绕过防盗链

### IAM安全挑战

**Cognito身份池利用**：
```bash
# 获取身份ID
aws cognito-identity get-id --identity-pool-id "us-east-1:xxx"
# 获取临时凭据
aws cognito-identity get-credentials-for-identity --identity-id "xxx"
```

### K8S云原生渗透

**攻击路径**：
```
普通用户 → 创建Pod(挂载hostPath) → Node权限 → 容忍度绕过 → Master权限
```

**核心技术**：
- hostPath挂载Node根目录
- tolerations绕过Master污点(Taints)
- kubeconfig配置文件利用

---

## 应急响应方法论

### 标准化排查流程

```
日志分析 → 异常账户 → 恶意文件 → 后门清除 → 加固修复
```

### 关键排查点

| 排查项 | 位置/命令 | 关注内容 |
|--------|-----------|----------|
| **Web日志** | access.log | 异常请求路径、攻击IP |
| **隐藏账户** | lusrmgr.msc、注册表 | 以$结尾的账户 |
| **计划任务** | 任务计划程序库 | 异常执行 |
| **进程分析** | 任务管理器 | CPU异常占用 |
| **网络连接** | netstat -ano | 异常外联IP |

---

## 核心洞察

1. **链式思维**：单个漏洞价值有限，漏洞链才能完成完整攻击
2. **经验驱动**："内网密码复用"是横向移动的重要经验判断
3. **无工具场景**：无CS/MSF时用certutil+正向连接替代
4. **云原生攻击面**：K8S的hostPath+tolerations是新突破口
5. **隐蔽性悖论**：最隐蔽的攻击利用合法功能而非漏洞
