# AWS账号组织策略检查工具

这个工具用于检查AWS账号中所有服务的策略，确保在将账号从一个组织迁移到另一个组织之前，没有与组织相关的配置。

## 功能特性

- 🔍 **全面检查**: 检查多个AWS服务的策略配置
- 🎯 **精准识别**: 仅检查客户管理的IAM策略，跳过AWS管理策略
- 📊 **详细报告**: 生成多种格式的详细问题报告
- 📄 **单独输出**: 将包含组织相关配置的策略和资源单独输出到专门文件
- 🚀 **易于使用**: 支持命令行参数和调试模式
- ☁️ **CloudShell优化**: 针对AWS CloudShell环境进行了优化

## 检查的服务

1. **IAM** - 仅检查客户管理的策略和角色信任策略
   - 角色信任策略
   - 附加到角色的客户管理策略
   - 附加到用户的客户管理策略
   - 独立的客户管理策略
2. **S3** - 存储桶策略
3. **KMS** - 密钥策略
4. **Lambda** - 函数资源策略
5. **SNS** - 主题策略
6. **SQS** - 队列策略
7. **ECR** - 仓库策略
8. **Secrets Manager** - 资源策略
9. **CloudWatch Logs** - 资源策略
10. **API Gateway** - 资源策略

## 检查的组织相关关键词

- `aws:PrincipalOrgID` - 组织主体ID条件
- `aws:PrincipalOrgPaths` - 组织路径条件
- `aws:ResourceOrgID` - 资源组织ID条件
- `aws:ResourceOrgPaths` - 资源组织路径条件
- `aws:SourceOrgID` - 源组织ID条件
- `aws:SourceOrgPaths` - 源组织路径条件
- `organizations:` - 组织服务相关
- `o-[a-z0-9]{10}` - 组织ID格式
- `ou-[a-z0-9]+-[a-z0-9]{8}` - 组织单元ID格式

## 使用方法

### 快速开始

```bash
# 给脚本添加执行权限
chmod +x check-org-policies.sh

# 运行检查（原版本）
./check-org-policies.sh

# 运行优化版本（推荐）
./check-org-policies-optimized.sh
```

### 基本使用

```bash
# 运行检查（原版本）
./check-org-policies.sh

# 运行优化版本（并行化处理，性能更好）
./check-org-policies-optimized.sh

# 调试模式运行
DEBUG=1 ./check-org-policies.sh
DEBUG=1 ./check-org-policies-optimized.sh
```

### 优化版本使用

```bash
# 使用默认并行任务数（10个）
./check-org-policies-optimized.sh

# 自定义并行任务数
MAX_PARALLEL_JOBS=20 ./check-org-policies-optimized.sh

# 适用于资源受限环境
MAX_PARALLEL_JOBS=5 ./check-org-policies-optimized.sh

# 同时设置调试模式和并行任务数
DEBUG=1 MAX_PARALLEL_JOBS=15 ./check-org-policies-optimized.sh
```

### 测试工具

```bash
# 测试CloudShell环境兼容性
./test-cloudshell.sh

# 测试客户管理IAM策略检查功能
./test-iam-customer-policies.sh

# 验证优化版本功能
./verify-optimization.sh

# 性能测试（对比原版本和优化版本）
./performance-test.sh

# jq修复验证
./test-jq-fix.sh

# 并发性能测试（推荐）
./test-concurrency.sh
```

## 版本说明

### 原版本 (check-org-policies.sh)
- 稳定可靠的顺序执行
- 适合小规模环境
- 兼容性最佳

### 优化版本 v1 (check-org-policies-optimized.sh)
- **并行化处理**: IAM检查支持并行执行
- **已知问题**: 并发实现有缺陷，实际并发度不高
- **状态**: 不推荐使用

### 优化版本 v2 (check-org-policies-optimized-v2.sh) ⭐ 强烈推荐
- **修复并发问题**: 正确实现真正的并行处理
- **CloudShell优化**: 自动检测CloudShell环境并优化配置
- **性能提升**: 3-8倍性能提升（取决于环境和资源数量）
- **智能配置**: 根据环境自动选择最佳并发数
- **进度显示**: 实时显示处理进度
- **向后兼容**: 输出格式与原版本完全兼容

### CloudShell 环境并发建议

| 配置类型 | 推荐并发数 | 适用场景 |
|----------|------------|----------|
| **保守配置** | 5 | 首次使用、网络不稳定 |
| **平衡配置** | 8 | 日常使用（推荐） |
| **激进配置** | 10-12 | 资源充足、追求速度 |

### 性能对比

| 环境规模 | 原版本耗时 | 优化版本耗时 | 性能提升 |
|----------|------------|--------------|----------|
| 小规模 (< 50个IAM资源) | ~30秒 | ~10秒 | 3倍 |
| 中等规模 (50-200个IAM资源) | ~2分钟 | ~30秒 | 4倍 |
| 大规模 (> 200个IAM资源) | ~5分钟 | ~1分钟 | 5倍 |

## 前置要求

- AWS CLI v2
- jq (JSON处理工具)
- 配置好的AWS凭证
- CloudShell环境或支持Bash的Linux/macOS环境

### AWS权限要求

确保你的AWS凭证具有以下权限：

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "iam:ListRoles",
                "iam:GetRole",
                "iam:ListAttachedRolePolicies",
                "iam:ListUsers",
                "iam:ListAttachedUserPolicies",
                "iam:ListPolicies",
                "iam:GetPolicy",
                "iam:GetPolicyVersion",
                "s3:ListAllMyBuckets",
                "s3:GetBucketPolicy",
                "kms:ListKeys",
                "kms:GetKeyPolicy",
                "lambda:ListFunctions",
                "lambda:GetPolicy",
                "sns:ListTopics",
                "sns:GetTopicAttributes",
                "sqs:ListQueues",
                "sqs:GetQueueAttributes",
                "ecr:DescribeRepositories",
                "ecr:GetRepositoryPolicy",
                "secretsmanager:ListSecrets",
                "secretsmanager:GetResourcePolicy",
                "logs:DescribeResourcePolicies",
                "apigateway:GET"
            ],
            "Resource": "*"
        }
    ]
}
```

## 输出文件

工具会在 `logs/` 目录下生成以下文件：

- **主日志文件** (`logs/org-policy-check-YYYYMMDD-HHMMSS.log`): 包含发现的问题和错误信息
- **详细日志文件** (`logs/org-policy-detailed-YYYYMMDD-HHMMSS.log`): 包含所有检查项目的详细记录，包括：
  - 每个检查的资源名称
  - 检查状态（正常/有问题/无策略等）
  - 详细的检查结果说明
- **JSON报告** (`logs/org-policy-issues-YYYYMMDD-HHMMSS.json`): 包含所有问题和检查记录的结构化数据
- **组织相关发现** (`logs/org-policy-findings-YYYYMMDD-HHMMSS.txt`): **重要文件** - 包含所有检测到的组织相关策略的完整内容

## 输出示例

### 成功情况（无问题）
```
🚀 开始AWS账号组织策略检查...
检查时间: 2024-06-30 10:00:00
==================================================
🔍 检查IAM策略 (仅客户管理策略)...
🔍 检查S3存储桶策略...
🔍 检查KMS密钥策略...
🔍 检查Lambda函数资源策略...
🔍 检查SNS主题策略...
🔍 检查SQS队列策略...

==================================================
📊 检查结果总结
==================================================
总检查项目: 10
发现问题: 0

✅ 未发现组织相关的策略配置问题
✅ 账号可以安全迁移

检查完成时间: 2024-06-30 10:00:15
```

### 发现问题情况
```
🚀 开始AWS账号组织策略检查...
检查时间: 2024-06-30 10:00:00
==================================================
🔍 检查IAM策略 (仅客户管理策略)...
❌ [IAM] Role:MyRole: 信任策略包含组织相关配置
❌ [IAM] Policy:arn:aws:iam::123456789012:policy/MyPolicy: 客户管理策略包含组织相关配置
🔍 检查S3存储桶策略...
❌ [S3] Bucket:my-bucket: 存储桶策略包含组织相关配置

==================================================
📊 检查结果总结
==================================================
总检查项目: 10
发现问题: 3

❌ 发现 3 个与组织相关的策略配置问题

问题摘要:
  - IAM: 2 个问题
  - S3: 1 个问题

组织相关发现摘要:
  - 共发现 3 个包含组织相关配置的资源
  - 详细策略内容已保存到: logs/org-policy-findings-20240630-100015.txt

⚠️  建议在迁移账号前修复这些问题

检查完成时间: 2024-06-30 10:00:15

文件输出位置:
- 主日志: logs/org-policy-check-20240630-100015.log
- 详细日志: logs/org-policy-detailed-20240630-100015.log
- JSON报告: logs/org-policy-issues-20240630-100015.json
- 组织相关发现: logs/org-policy-findings-20240630-100015.txt (包含 3 个发现)
```

### 组织相关发现文件示例

`logs/org-policy-findings-YYYYMMDD-HHMMSS.txt` 文件内容：

```
AWS账号组织策略检查 - 组织相关发现
检查时间: 2024-06-30 10:00:00
========================================

Role Trust Policy: MyRole
Policy Content: {
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "*"
      },
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringEquals": {
          "aws:PrincipalOrgID": "o-1234567890"
        }
      }
    }
  ]
}
---
Customer Managed Policy: arn:aws:iam::123456789012:policy/MyPolicy (attached to role: MyRole)
Policy Content: {
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "s3:GetObject",
      "Resource": "*",
      "Condition": {
        "StringEquals": {
          "aws:PrincipalOrgID": "o-1234567890"
        }
      }
    }
  ]
}
---
S3 Bucket Policy: my-bucket
Policy Content: {
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": "*",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::my-bucket/*",
      "Condition": {
        "StringEquals": {
          "aws:PrincipalOrgID": "o-1234567890"
        }
      }
    }
  ]
}
---

========================================
检查总结:
- 检查完成时间: 2024-06-30 10:00:15
- 总检查项目: 10
- 发现问题: 3
- 组织相关发现: 3
```

## 重要特性说明

### IAM策略检查优化

- **仅检查客户管理策略**: 自动跳过所有AWS管理策略（如 `arn:aws:iam::aws:policy/*`）
- **三种检查类型**:
  1. 角色信任策略（客户可控制）
  2. 附加到角色/用户的客户管理策略
  3. 独立的客户管理策略
- **统计信息**: 显示检查的角色、用户和客户管理策略数量

### 函数化设计

脚本采用模块化设计，每个服务检查都是独立函数：
- `check_iam_policies()` - IAM策略检查
- `check_s3_policies()` - S3策略检查
- `check_kms_policies()` - KMS策略检查
- 等等...

可以通过注释特定函数调用来跳过不需要的检查。

## 故障排除

### 常见问题

1. **权限不足**
   - 确保AWS凭证具有必要的读取权限
   - 检查IAM策略是否包含所有必需的操作

2. **CloudShell中脚本退出**
   - 使用调试模式: `DEBUG=1 ./check-org-policies.sh`
   - 先运行测试脚本: `./test-cloudshell.sh`

3. **区域问题**
   - 某些服务是全局的（如IAM），某些是区域性的
   - 建议在主要使用的区域运行检查

4. **网络问题**
   - 确保网络连接正常
   - 检查是否有代理或防火墙限制

5. **jq参数错误**
   - 如果遇到 `jq: --arg takes two parameters` 错误
   - 运行 `./test-jq-fix.sh` 验证修复
   - 使用较小的并行任务数: `MAX_PARALLEL_JOBS=3 ./check-org-policies-optimized.sh`

6. **优化版本性能问题**
   - 并行任务过多导致系统卡顿: 减少 `MAX_PARALLEL_JOBS`
   - AWS API限流: 进一步减少并行任务数
   - 内存不足: 使用 `MAX_PARALLEL_JOBS=2` 或更小值

### 调试模式

启用调试模式获取更详细的执行信息：
```bash
DEBUG=1 ./check-org-policies.sh
```

## 迁移建议

如果发现组织相关的策略配置：

1. **查看详细发现**: 重点查看 `logs/org-policy-findings-*.txt` 文件
2. **记录所有问题**: 保存生成的所有报告文件
3. **逐一修复**: 根据发现文件中的详细策略内容修复每个问题
4. **重新检查**: 修复后重新运行工具确认问题已解决
5. **备份策略**: 在修改前备份原始策略
6. **测试功能**: 修改后测试相关功能是否正常

### 修复优先级

1. **IAM角色信任策略** - 最高优先级，影响角色可用性
2. **客户管理IAM策略** - 高优先级，影响权限控制
3. **资源策略** (S3, KMS, Lambda等) - 中等优先级，影响资源访问

## 贡献

欢迎提交问题报告和改进建议！

## 许可证

MIT License
