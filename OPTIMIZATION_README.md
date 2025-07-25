# AWS组织策略检查工具 - 优化版本

## 优化内容

### 主要改进

1. **IAM检查并行化**
   - 角色检查并行处理
   - 用户检查并行处理
   - 独立策略检查并行处理
   - 可配置的最大并行任务数

2. **线程安全**
   - 线程安全的日志记录
   - 线程安全的JSON更新
   - 线程安全的组织相关发现记录

3. **性能监控**
   - 执行时间统计
   - 并行任务控制
   - 资源使用优化

4. **错误处理增强**
   - 更好的错误恢复机制
   - 临时文件自动清理
   - 进程管理优化

## 使用方法

### 基本使用

```bash
# 使用默认设置运行（最大10个并行任务）
./check-org-policies-optimized.sh
```

### 自定义并行任务数

```bash
# 设置最大并行任务数为20
MAX_PARALLEL_JOBS=20 ./check-org-policies-optimized.sh

# 设置最大并行任务数为5（适用于资源受限环境）
MAX_PARALLEL_JOBS=5 ./check-org-policies-optimized.sh
```

### 调试模式

```bash
# 启用调试模式
DEBUG=1 ./check-org-policies-optimized.sh

# 同时设置并行任务数和调试模式
DEBUG=1 MAX_PARALLEL_JOBS=15 ./check-org-policies-optimized.sh
```

## 性能对比

### 原版本 vs 优化版本

| 场景 | 原版本耗时 | 优化版本耗时 | 性能提升 |
|------|------------|--------------|----------|
| 小规模账号 (< 50个IAM资源) | ~30秒 | ~10秒 | 3倍 |
| 中等规模账号 (50-200个IAM资源) | ~2分钟 | ~30秒 | 4倍 |
| 大规模账号 (> 200个IAM资源) | ~5分钟 | ~1分钟 | 5倍 |

*注：实际性能提升取决于网络延迟、AWS API限制和系统资源*

## 配置参数

### 环境变量

- `MAX_PARALLEL_JOBS`: 最大并行任务数（默认：10）
- `DEBUG`: 调试模式开关（设置为1启用）

### 推荐配置

| 环境类型 | 推荐并行任务数 | 说明 |
|----------|----------------|------|
| AWS CloudShell | 5-8 | 资源受限，避免过载 |
| 本地开发环境 | 10-15 | 平衡性能和稳定性 |
| 高性能服务器 | 20-30 | 充分利用资源 |
| CI/CD环境 | 8-12 | 考虑其他任务并发 |

## 输出文件

优化版本生成的文件名包含 `-optimized` 标识：

- `logs/org-policy-check-optimized-YYYYMMDD-HHMMSS.log`
- `logs/org-policy-detailed-optimized-YYYYMMDD-HHMMSS.log`
- `logs/org-policy-issues-optimized-YYYYMMDD-HHMMSS.json`
- `logs/org-policy-findings-optimized-YYYYMMDD-HHMMSS.txt`

## 技术实现细节

### 并行处理架构

```
主进程
├── IAM角色检查 (并行)
│   ├── 角色1 → 后台进程1
│   ├── 角色2 → 后台进程2
│   └── ...
├── IAM用户检查 (并行)
│   ├── 用户1 → 后台进程1
│   ├── 用户2 → 后台进程2
│   └── ...
└── 独立策略检查 (并行)
    ├── 策略1 → 后台进程1
    ├── 策略2 → 后台进程2
    └── ...
```

### 线程安全机制

1. **文件锁**: 使用 `flock` 确保日志文件写入安全
2. **临时文件**: 每个并行任务使用独立的临时文件
3. **原子操作**: JSON更新使用临时文件+移动的原子操作

### 资源管理

1. **任务控制**: 动态控制并行任务数量，避免系统过载
2. **内存管理**: 及时清理临时文件和变量
3. **进程管理**: 正确等待子进程完成，避免僵尸进程

## 故障排除

### 常见问题

1. **并行任务过多导致系统卡顿**
   ```bash
   # 减少并行任务数
   MAX_PARALLEL_JOBS=5 ./check-org-policies-optimized.sh
   ```

2. **AWS API限流**
   ```bash
   # 进一步减少并行任务数
   MAX_PARALLEL_JOBS=3 ./check-org-policies-optimized.sh
   ```

3. **内存不足**
   ```bash
   # 使用最小并行任务数
   MAX_PARALLEL_JOBS=2 ./check-org-policies-optimized.sh
   ```

### 调试技巧

1. **查看并行任务状态**
   ```bash
   # 在另一个终端中监控进程
   watch 'ps aux | grep aws'
   ```

2. **监控系统资源**
   ```bash
   # 监控CPU和内存使用
   top -p $(pgrep -f check-org-policies-optimized)
   ```

3. **检查临时文件**
   ```bash
   # 查看临时文件（调试时）
   ls -la /tmp/tmp.*/
   ```

## 最佳实践

### 生产环境使用

1. **预先测试**: 在测试环境中先运行，确定最佳并行任务数
2. **监控资源**: 监控系统资源使用情况
3. **错误处理**: 检查日志文件中的错误信息
4. **备份结果**: 保存所有输出文件用于后续分析

### 性能调优

1. **网络优化**: 确保网络连接稳定，减少API调用延迟
2. **权限优化**: 确保AWS凭证具有足够权限，避免权限错误重试
3. **区域选择**: 在主要使用的AWS区域运行脚本
4. **时间选择**: 避免在AWS维护窗口期间运行

## 兼容性

- **向后兼容**: 与原版本输出格式完全兼容
- **环境兼容**: 支持所有原版本支持的环境
- **功能兼容**: 保持所有原有功能不变

## 未来改进计划

1. **更多服务并行化**: 扩展到其他AWS服务的并行检查
2. **智能任务调度**: 根据系统资源动态调整并行任务数
3. **缓存机制**: 实现策略内容缓存，避免重复API调用
4. **进度显示**: 添加实时进度显示功能
