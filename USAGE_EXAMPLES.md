# 使用示例

## 基本使用

### 1. 运行原版本
```bash
./check-org-policies.sh
```

### 2. 运行优化版本（推荐）
```bash
./check-org-policies-optimized.sh
```

## 高级配置

### 1. 自定义并行任务数
```bash
# 高性能环境
MAX_PARALLEL_JOBS=20 ./check-org-policies-optimized.sh

# 资源受限环境
MAX_PARALLEL_JOBS=5 ./check-org-policies-optimized.sh

# AWS CloudShell 推荐配置
MAX_PARALLEL_JOBS=8 ./check-org-policies-optimized.sh
```

### 2. 调试模式
```bash
# 启用详细调试信息
DEBUG=1 ./check-org-policies-optimized.sh

# 组合使用
DEBUG=1 MAX_PARALLEL_JOBS=5 ./check-org-policies-optimized.sh
```

## 测试和验证

### 1. 功能验证
```bash
# 验证优化版本功能正确性
./verify-optimization.sh
```

### 2. 性能测试
```bash
# 对比原版本和优化版本性能
./performance-test.sh
```

### 3. 环境兼容性测试
```bash
# 测试CloudShell环境
./test-cloudshell.sh
```

## 实际使用场景

### 场景1: 生产环境快速检查
```bash
# 使用推荐配置快速检查
MAX_PARALLEL_JOBS=10 ./check-org-policies-optimized.sh

# 检查结果
ls -la logs/org-policy-*-optimized-*
```

### 场景2: 大规模环境优化
```bash
# 高并发配置
MAX_PARALLEL_JOBS=25 ./check-org-policies-optimized.sh
```

### 场景3: 资源受限环境
```bash
# 低并发配置
MAX_PARALLEL_JOBS=3 ./check-org-policies-optimized.sh
```

### 场景4: CI/CD 集成
```bash
#!/bin/bash
# 在CI/CD管道中使用

# 设置适中的并行任务数
export MAX_PARALLEL_JOBS=8

# 运行检查
./check-org-policies-optimized.sh

# 检查是否发现问题
issues_count=$(jq -r '.summary.issues_found' logs/org-policy-issues-optimized-*.json)

if [ "$issues_count" -gt 0 ]; then
    echo "发现 $issues_count 个组织相关策略问题"
    exit 1
else
    echo "未发现组织相关策略问题"
    exit 0
fi
```

## 输出文件说明

### 优化版本输出文件
- `logs/org-policy-check-optimized-YYYYMMDD-HHMMSS.log` - 主日志
- `logs/org-policy-detailed-optimized-YYYYMMDD-HHMMSS.log` - 详细日志
- `logs/org-policy-issues-optimized-YYYYMMDD-HHMMSS.json` - JSON格式报告
- `logs/org-policy-findings-optimized-YYYYMMDD-HHMMSS.txt` - 组织相关发现详情

### 查看结果
```bash
# 查看最新的检查结果
cat logs/org-policy-check-optimized-*.log | tail -20

# 查看JSON报告摘要
jq '.summary' logs/org-policy-issues-optimized-*.json

# 查看发现的问题
jq '.issues[]' logs/org-policy-issues-optimized-*.json

# 查看组织相关发现
cat logs/org-policy-findings-optimized-*.txt
```

## 故障排除

### 常见问题及解决方案

1. **脚本执行缓慢**
   ```bash
   # 减少并行任务数
   MAX_PARALLEL_JOBS=5 ./check-org-policies-optimized.sh
   ```

2. **AWS API限流错误**
   ```bash
   # 进一步减少并行任务数
   MAX_PARALLEL_JOBS=2 ./check-org-policies-optimized.sh
   ```

3. **内存不足**
   ```bash
   # 使用最小并行配置
   MAX_PARALLEL_JOBS=1 ./check-org-policies-optimized.sh
   ```

4. **权限错误**
   ```bash
   # 检查AWS凭证
   aws sts get-caller-identity
   
   # 检查权限
   aws iam list-roles --max-items 1
   ```

### 调试技巧

1. **监控系统资源**
   ```bash
   # 在另一个终端监控
   watch 'ps aux | grep check-org-policies'
   top -p $(pgrep -f check-org-policies)
   ```

2. **查看实时日志**
   ```bash
   # 实时查看日志
   tail -f logs/org-policy-check-optimized-*.log
   ```

3. **检查临时文件**
   ```bash
   # 查看临时文件（调试时）
   ls -la /tmp/tmp.*/
   ```

## 最佳实践

1. **首次使用建议**
   - 先运行 `./verify-optimization.sh` 验证环境
   - 使用较小的并行任务数开始测试
   - 检查输出文件确保功能正常

2. **生产环境使用**
   - 根据环境资源选择合适的并行任务数
   - 定期保存检查结果用于审计
   - 在非高峰时段运行以避免影响其他工作负载

3. **性能优化**
   - 使用 `./performance-test.sh` 找到最佳配置
   - 监控AWS API使用情况避免限流
   - 考虑网络延迟对性能的影响
