# AWS账号组织策略检查工具

这个工具用于检查AWS账号中所有服务的策略，确保在将账号从一个组织迁移到另一个组织之前，没有与组织相关的配置。

## 功能特性

- 🔍 **全面检查**: 检查多个AWS服务的策略配置
- 📊 **详细报告**: 生成JSON格式的详细问题报告
- 🎯 **精准识别**: 识别组织相关的关键词和配置
- 🚀 **易于使用**: 支持命令行参数和多种运行方式

## 检查的服务

1. **IAM** - 角色、用户、策略
2. **S3** - 存储桶策略
3. **KMS** - 密钥策略
4. **Lambda** - 函数资源策略
5. **SNS** - 主题策略
6. **SQS** - 队列策略
7. **ECR** - 仓库策略 (仅Bash版本)
8. **Secrets Manager** - 资源策略 (仅Bash版本)
9. **CloudWatch Logs** - 资源策略 (仅Bash版本)
10. **API Gateway** - 资源策略 (仅Bash版本)

## 检查的组织相关关键词

- `aws:PrincipalOrgID` - 组织主体ID条件
- `aws:PrincipalOrgPaths` - 组织路径条件
- `aws:RequestedRegion` - 请求区域条件
- `organizations:` - 组织服务相关
- `o-[a-z0-9]{10}` - 组织ID格式
- `ou-[a-z0-9]+-[a-z0-9]{8}` - 组织单元ID格式
- `r-[a-z0-9]{4}` - 根ID格式

## 使用方法

### 快速开始

```bash
# 1. 设置环境（首次运行）
./setup.sh

# 2. 运行检查
./run_check.sh

# 3. 或者使用Bash版本
./check-org-policies.sh
```

### Python版本 (推荐)

```bash
# 使用包装脚本（推荐）
./run_check.sh

# 指定AWS配置文件
./run_check.sh --profile my-profile

# 指定区域
./run_check.sh --region us-west-2

# 同时指定配置文件和区域
./run_check.sh --profile my-profile --region eu-west-1

# 直接使用虚拟环境
source venv/bin/activate
python3 check_org_policies.py
deactivate
```

### Bash版本

```bash
# 给脚本添加执行权限
chmod +x check-org-policies.sh

# 运行检查
./check-org-policies.sh
```

## 前置要求

### Python版本
- Python 3.6+
- boto3库: `pip install boto3`
- 配置好的AWS凭证

### Bash版本
- AWS CLI v2
- jq (JSON处理工具)
- 配置好的AWS凭证

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

## 输出示例

### 成功情况（无问题）
```
🚀 开始AWS账号组织策略检查...
检查时间: 2024-06-30 10:00:00
==================================================
🔍 检查IAM策略...
🔍 检查S3存储桶策略...
🔍 检查KMS密钥策略...
🔍 检查Lambda函数资源策略...
🔍 检查SNS主题策略...
🔍 检查SQS队列策略...

==================================================
📊 检查结果总结
==================================================
总检查项目: 6
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
🔍 检查IAM策略...
❌ [IAM] Role:MyRole: 信任策略包含组织相关配置
🔍 检查S3存储桶策略...
❌ [S3] Bucket:my-bucket: 存储桶策略包含组织相关配置

==================================================
📊 检查结果总结
==================================================
总检查项目: 6
发现问题: 2

❌ 发现 2 个与组织相关的策略配置问题:

🔸 IAM (1 个问题):
  - Role:MyRole: 信任策略包含组织相关配置
    关键词: aws:PrincipalOrgID

🔸 S3 (1 个问题):
  - Bucket:my-bucket: 存储桶策略包含组织相关配置
    关键词: o-1234567890

📄 详细报告已保存到: org-policy-issues-20240630-100015.json
⚠️  建议在迁移账号前修复这些问题

检查完成时间: 2024-06-30 10:00:15
```

## 报告文件

工具会生成以下文件：

- **主日志文件** (`org-policy-check-YYYYMMDD-HHMMSS.log`): 包含发现的问题和错误信息
- **详细日志文件** (`org-policy-detailed-YYYYMMDD-HHMMSS.log`): 包含所有检查项目的详细记录，包括：
  - 每个检查的资源名称
  - 检查状态（正常/有问题/无策略等）
  - 详细的检查结果说明
- **JSON报告** (`org-policy-issues-YYYYMMDD-HHMMSS.json`): 包含所有问题和检查记录的结构化数据

## 故障排除

### 常见问题

1. **权限不足**
   - 确保AWS凭证具有必要的读取权限
   - 检查IAM策略是否包含所有必需的操作

2. **区域问题**
   - 某些服务是全局的（如IAM），某些是区域性的
   - 建议在主要使用的区域运行检查

3. **网络问题**
   - 确保网络连接正常
   - 检查是否有代理或防火墙限制

### 调试模式

对于Python版本，你可以修改代码添加更详细的日志输出。

## 迁移建议

如果发现组织相关的策略配置：

1. **记录所有问题**: 保存生成的报告文件
2. **逐一修复**: 根据报告中的详细信息修复每个问题
3. **重新检查**: 修复后重新运行工具确认问题已解决
4. **备份策略**: 在修改前备份原始策略
5. **测试功能**: 修改后测试相关功能是否正常

## 贡献

欢迎提交问题报告和改进建议！

## 许可证

MIT License
