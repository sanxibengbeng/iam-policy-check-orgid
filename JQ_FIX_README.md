# jq 参数错误修复说明

## 问题描述

在运行优化版本脚本时，出现了以下错误：

```
jq: --arg takes two parameters (e.g. --arg varname value)
Use jq --help for help with command-line options,
or see the jq manpage, or online docs  at https://jqlang.github.io/jq
```

## 问题原因

这个错误是由于在并行处理过程中，某些变量可能为空或包含特殊字符，导致 jq 命令的参数不完整。主要问题出现在以下几个函数中：

1. `log_issue()` - 记录问题时的 JSON 更新
2. `log_check_detail()` - 记录详细信息时的 JSON 更新
3. `safe_json_update()` - JSON 更新函数的参数处理

## 修复内容

### 1. 修复 `safe_json_update()` 函数

**修复前：**
```bash
safe_json_update() {
    local update_cmd="$1"
    # ...
}
```

**修复后：**
```bash
safe_json_update() {
    local jq_args=("$@")
    
    (
        flock -x 200
        jq "${jq_args[@]}" "$ISSUES_FILE" > "$TEMP_DIR/tmp.json" && mv "$TEMP_DIR/tmp.json" "$ISSUES_FILE"
    ) 200>>"$ISSUES_FILE.lock"
}
```

### 2. 修复 `log_issue()` 函数

**修复前：**
```bash
safe_json_update --arg service "$service" --arg resource "$resource" --arg issue "$issue" --arg details "$details" \
   '.issues += [{"service": $service, "resource": $resource, "issue": $issue, "details": $details}] | .summary.issues_found += 1'
```

**修复后：**
```bash
# 确保参数不为空
local safe_service="${service:-unknown}"
local safe_resource="${resource:-unknown}"
local safe_issue="${issue:-unknown}"
local safe_details="${details:-}"

safe_json_update --arg service "$safe_service" --arg resource "$safe_resource" --arg issue "$safe_issue" --arg details "$safe_details" \
   '.issues += [{"service": $service, "resource": $resource, "issue": $issue, "details": $details}] | .summary.issues_found += 1'
```

### 3. 修复 `log_check_detail()` 函数

类似地添加了参数验证和默认值处理。

### 4. 增强并行处理函数

在所有并行处理函数中添加了：
- 输入参数验证
- 更好的错误处理
- 更详细的错误信息记录

## 验证修复

### 运行测试脚本

```bash
# 快速验证修复
./test-jq-fix.sh

# 完整功能验证
./verify-optimization.sh
```

### 手动测试

```bash
# 使用较小的并行任务数测试
MAX_PARALLEL_JOBS=3 ./check-org-policies-optimized.sh

# 检查是否还有jq错误
grep -i "jq:" logs/org-policy-*-optimized-*.log
```

## 修复效果

修复后的脚本具有以下改进：

1. **参数安全性**: 所有传递给 jq 的参数都经过验证和清理
2. **错误处理**: 更好的错误处理和恢复机制
3. **调试信息**: 更详细的错误信息便于排查问题
4. **稳定性**: 在各种边界条件下都能稳定运行

## 预防措施

为了避免类似问题再次发生，建议：

1. **参数验证**: 始终验证传递给外部命令的参数
2. **默认值**: 为可能为空的变量提供默认值
3. **错误处理**: 在所有外部命令调用处添加错误处理
4. **测试覆盖**: 增加边界条件和异常情况的测试

## 兼容性

修复后的版本：
- 保持与原版本的完全兼容性
- 输出格式不变
- 功能特性不变
- 性能优化保持不变

## 使用建议

1. **首次使用**: 建议先运行 `./test-jq-fix.sh` 验证环境
2. **生产环境**: 使用适中的并行任务数（5-10）
3. **调试模式**: 遇到问题时启用 `DEBUG=1`
4. **监控日志**: 定期检查日志文件中的错误信息
