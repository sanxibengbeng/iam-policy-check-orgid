#!/bin/bash

# AWS账号组织策略检查脚本 - 优化版本
# 用于检查账号中所有服务的策略是否包含组织相关配置
# 主要优化：IAM检查并行化处理

# 改进错误处理 - 不要在管道失败时立即退出
set -o pipefail

# 调试模式 - 如果设置了DEBUG环境变量则启用
if [ "${DEBUG:-}" = "1" ]; then
    set -x
fi

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 并行处理配置
MAX_PARALLEL_JOBS=${MAX_PARALLEL_JOBS:-10}  # 默认最大并行任务数
TEMP_DIR=$(mktemp -d)
trap "rm -rf $TEMP_DIR" EXIT

# 创建logs目录
LOGS_DIR="logs"
mkdir -p "$LOGS_DIR"

# 日志文件
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
LOG_FILE="$LOGS_DIR/org-policy-check-optimized-$TIMESTAMP.log"
DETAILED_LOG_FILE="$LOGS_DIR/org-policy-detailed-optimized-$TIMESTAMP.log"
ISSUES_FILE="$LOGS_DIR/org-policy-issues-optimized-$TIMESTAMP.json"
ORG_FINDINGS_FILE="$LOGS_DIR/org-policy-findings-optimized-$TIMESTAMP.txt"

echo -e "${BLUE}=== AWS账号组织策略检查工具 (优化版本) ===${NC}"
echo "最大并行任务数: $MAX_PARALLEL_JOBS"
echo "主日志文件: $LOG_FILE"
echo "详细日志文件: $DETAILED_LOG_FILE"
echo "问题报告: $ISSUES_FILE"
echo "组织相关发现: $ORG_FINDINGS_FILE"
echo ""

# 初始化问题报告文件
echo '{"issues": [], "summary": {"total_checks": 0, "issues_found": 0}, "check_details": []}' > "$ISSUES_FILE"

# 初始化组织相关发现文件
echo "AWS账号组织策略检查 - 组织相关发现 (优化版本)" > "$ORG_FINDINGS_FILE"
echo "检查时间: $(date)" >> "$ORG_FINDINGS_FILE"
echo "========================================" >> "$ORG_FINDINGS_FILE"
echo "" >> "$ORG_FINDINGS_FILE"

# 初始化日志文件
echo "AWS账号组织策略检查 (优化版本) - $(date)" > "$LOG_FILE"
echo "========================================" >> "$LOG_FILE"
echo ""

echo "AWS账号组织策略检查详细日志 (优化版本) - $(date)" > "$DETAILED_LOG_FILE"
echo "========================================" >> "$DETAILED_LOG_FILE"
echo ""

# 线程安全的日志记录函数
safe_log() {
    local message="$1"
    local file="$2"
    
    # 使用文件锁确保线程安全
    (
        flock -x 200
        echo "$message" >> "$file"
    ) 200>>"$file.lock"
}

# 线程安全的JSON更新函数
safe_json_update() {
    local update_cmd="$1"
    
    (
        flock -x 200
        jq "$update_cmd" "$ISSUES_FILE" > "$TEMP_DIR/tmp.json" && mv "$TEMP_DIR/tmp.json" "$ISSUES_FILE"
    ) 200>>"$ISSUES_FILE.lock"
}

# 错误处理函数
handle_error() {
    local service="$1"
    local operation="$2"
    local error_msg="$3"
    
    echo -e "${YELLOW}[警告] $service - $operation: $error_msg${NC}"
    safe_log "WARNING: $service - $operation: $error_msg" "$LOG_FILE"
    log_check_detail "$service" "$operation" "错误" "$error_msg"
}

# 记录问题的函数
log_issue() {
    local service="$1"
    local resource="$2"
    local issue="$3"
    local details="$4"
    
    echo -e "${RED}[问题] $service - $resource: $issue${NC}"
    safe_log "$service - $resource: $issue - $details" "$LOG_FILE"
    
    # 添加到JSON报告
    safe_json_update --arg service "$service" --arg resource "$resource" --arg issue "$issue" --arg details "$details" \
       '.issues += [{"service": $service, "resource": $resource, "issue": $issue, "details": $details}] | .summary.issues_found += 1'
}

# 记录详细检查信息
log_check_detail() {
    local service="$1"
    local resource="$2"
    local status="$3"
    local message="$4"
    
    safe_log "[$service] $resource: $status - $message" "$DETAILED_LOG_FILE"
    
    # 添加到JSON报告的详细记录
    safe_json_update --arg service "$service" --arg resource "$resource" --arg status "$status" --arg message "$message" \
       '.check_details += [{"service": $service, "resource": $resource, "status": $status, "message": $message, "timestamp": now | strftime("%Y-%m-%d %H:%M:%S")}]'
}

# 更新检查计数
update_check_count() {
    safe_json_update '.summary.total_checks += 1'
}

# 线程安全的组织相关发现记录
log_org_finding() {
    local finding_type="$1"
    local resource_name="$2"
    local policy_content="$3"
    
    (
        flock -x 200
        echo "$finding_type: $resource_name" >> "$ORG_FINDINGS_FILE"
        echo "Policy Content: $policy_content" >> "$ORG_FINDINGS_FILE"
        echo "---" >> "$ORG_FINDINGS_FILE"
    ) 200>>"$ORG_FINDINGS_FILE.lock"
}

# 检查字符串中是否包含组织相关关键词
check_org_keywords() {
    local content="$1"
    local keywords=(
        "aws:PrincipalOrgID"
        "aws:PrincipalOrgPaths"
        "aws:ResourceOrgID"
        "aws:ResourceOrgPaths"
        "aws:SourceOrgID"
        "aws:SourceOrgPaths"
        "organizations:"
        "o-[a-z0-9]{10}"
        "ou-[a-z0-9]+-[a-z0-9]{8}"
    )
    
    for keyword in "${keywords[@]}"; do
        if echo "$content" | grep -qi "$keyword"; then
            return 0
        fi
    done
    return 1
}

# 并行处理IAM角色的函数
process_iam_role() {
    local role="$1"
    local temp_file="$TEMP_DIR/role_$role.tmp"
    
    {
        echo "检查角色: $role"
        log_check_detail "IAM" "Role:$role" "检查中" "检查角色信任策略"
        
        # 获取角色信任策略
        policy_doc=$(aws iam get-role --role-name "$role" --query 'Role.AssumeRolePolicyDocument' --output text 2>/dev/null || echo "")
        if [ -n "$policy_doc" ] && [ "$policy_doc" != "None" ]; then
            if check_org_keywords "$policy_doc"; then
                log_issue "IAM" "Role:$role" "信任策略包含组织相关配置" "$policy_doc"
                log_check_detail "IAM" "Role:$role" "有问题" "信任策略包含组织相关配置"
                log_org_finding "Role Trust Policy" "$role" "$policy_doc"
                echo "ISSUE_FOUND" >> "$temp_file"
            else
                log_check_detail "IAM" "Role:$role" "正常" "信任策略无组织相关配置"
            fi
        else
            log_check_detail "IAM" "Role:$role" "无策略" "未找到信任策略"
        fi
        
        # 检查附加的客户管理策略
        aws iam list-attached-role-policies --role-name "$role" --query 'AttachedPolicies[].PolicyArn' --output text 2>/dev/null | tr '\t' '\n' | while read -r policy_arn; do
            if [ -n "$policy_arn" ] && [ "$policy_arn" != "None" ]; then
                # 只检查客户管理的策略
                if [[ "$policy_arn" != *"arn:aws:iam::aws:policy"* ]]; then
                    log_check_detail "IAM" "Policy:$policy_arn" "检查中" "检查客户管理策略"
                    
                    version_id=$(aws iam get-policy --policy-arn "$policy_arn" --query 'Policy.DefaultVersionId' --output text 2>/dev/null || echo "")
                    if [ -n "$version_id" ] && [ "$version_id" != "None" ]; then
                        policy_content=$(aws iam get-policy-version --policy-arn "$policy_arn" --version-id "$version_id" --query 'PolicyVersion.Document' --output text 2>/dev/null || echo "")
                        if [ -n "$policy_content" ] && [ "$policy_content" != "None" ]; then
                            if check_org_keywords "$policy_content"; then
                                log_issue "IAM" "Policy:$policy_arn" "客户管理策略包含组织相关配置" "$policy_content"
                                log_check_detail "IAM" "Policy:$policy_arn" "有问题" "客户管理策略包含组织相关配置"
                                log_org_finding "Customer Managed Policy" "$policy_arn (attached to role: $role)" "$policy_content"
                                echo "ISSUE_FOUND" >> "$temp_file"
                            else
                                log_check_detail "IAM" "Policy:$policy_arn" "正常" "客户管理策略无组织相关配置"
                            fi
                        else
                            log_check_detail "IAM" "Policy:$policy_arn" "无内容" "策略内容为空"
                        fi
                    fi
                else
                    log_check_detail "IAM" "Policy:$policy_arn" "跳过" "AWS管理策略，已跳过"
                fi
            fi
        done
        
        echo "ROLE_PROCESSED" >> "$temp_file"
    } &
}

# 并行处理IAM用户的函数
process_iam_user() {
    local user="$1"
    local temp_file="$TEMP_DIR/user_$user.tmp"
    
    {
        echo "检查用户: $user"
        log_check_detail "IAM" "User:$user" "检查中" "检查用户附加的客户管理策略"
        
        aws iam list-attached-user-policies --user-name "$user" --query 'AttachedPolicies[].PolicyArn' --output text 2>/dev/null | tr '\t' '\n' | while read -r policy_arn; do
            if [ -n "$policy_arn" ] && [ "$policy_arn" != "None" ]; then
                # 只检查客户管理的策略
                if [[ "$policy_arn" != *"arn:aws:iam::aws:policy"* ]]; then
                    version_id=$(aws iam get-policy --policy-arn "$policy_arn" --query 'Policy.DefaultVersionId' --output text 2>/dev/null || echo "")
                    if [ -n "$version_id" ] && [ "$version_id" != "None" ]; then
                        policy_content=$(aws iam get-policy-version --policy-arn "$policy_arn" --version-id "$version_id" --query 'PolicyVersion.Document' --output text 2>/dev/null || echo "")
                        if [ -n "$policy_content" ] && [ "$policy_content" != "None" ]; then
                            if check_org_keywords "$policy_content"; then
                                log_issue "IAM" "UserPolicy:$user->$policy_arn" "用户的客户管理策略包含组织相关配置" "$policy_content"
                                log_check_detail "IAM" "UserPolicy:$user->$policy_arn" "有问题" "用户的客户管理策略包含组织相关配置"
                                log_org_finding "Customer Managed Policy" "$policy_arn (attached to user: $user)" "$policy_content"
                                echo "ISSUE_FOUND" >> "$temp_file"
                            else
                                log_check_detail "IAM" "UserPolicy:$user->$policy_arn" "正常" "用户的客户管理策略无组织相关配置"
                            fi
                        else
                            log_check_detail "IAM" "UserPolicy:$user->$policy_arn" "无内容" "策略内容为空"
                        fi
                    fi
                else
                    log_check_detail "IAM" "UserPolicy:$user->$policy_arn" "跳过" "AWS管理策略，已跳过"
                fi
            fi
        done
        
        echo "USER_PROCESSED" >> "$temp_file"
    } &
}

# 并行处理独立客户管理策略的函数
process_standalone_policy() {
    local policy_arn="$1"
    local temp_file="$TEMP_DIR/policy_$(echo "$policy_arn" | sed 's/[^a-zA-Z0-9]/_/g').tmp"
    
    {
        log_check_detail "IAM" "StandalonePolicy:$policy_arn" "检查中" "检查独立的客户管理策略"
        
        version_id=$(aws iam get-policy --policy-arn "$policy_arn" --query 'Policy.DefaultVersionId' --output text 2>/dev/null || echo "")
        if [ -n "$version_id" ] && [ "$version_id" != "None" ]; then
            policy_content=$(aws iam get-policy-version --policy-arn "$policy_arn" --version-id "$version_id" --query 'PolicyVersion.Document' --output text 2>/dev/null || echo "")
            if [ -n "$policy_content" ] && [ "$policy_content" != "None" ]; then
                if check_org_keywords "$policy_content"; then
                    log_issue "IAM" "StandalonePolicy:$policy_arn" "独立的客户管理策略包含组织相关配置" "$policy_content"
                    log_check_detail "IAM" "StandalonePolicy:$policy_arn" "有问题" "独立的客户管理策略包含组织相关配置"
                    log_org_finding "Standalone Customer Managed Policy" "$policy_arn" "$policy_content"
                    echo "ISSUE_FOUND" >> "$temp_file"
                else
                    log_check_detail "IAM" "StandalonePolicy:$policy_arn" "正常" "独立的客户管理策略无组织相关配置"
                fi
            else
                log_check_detail "IAM" "StandalonePolicy:$policy_arn" "无内容" "策略内容为空"
            fi
        fi
        
        echo "POLICY_PROCESSED" >> "$temp_file"
    } &
}

# 等待并行任务完成的函数
wait_for_jobs() {
    local max_jobs="$1"
    local current_jobs
    
    while true; do
        current_jobs=$(jobs -r | wc -l)
        if [ "$current_jobs" -lt "$max_jobs" ]; then
            break
        fi
        sleep 0.1
    done
}

# ========================================
# 优化的检查函数定义
# ========================================

# 1. 优化的IAM策略检查 - 并行化处理
check_iam_policies_optimized() {
    echo -e "${BLUE}1. 检查IAM策略 (仅客户管理策略) - 并行化处理${NC}"
    update_check_count
    
    local checked_roles=0
    local checked_users=0
    local checked_policies=0
    local customer_managed_policies=0
    
    echo "开始并行检查IAM角色..."
    
    # 获取所有角色列表
    local roles_list=$(aws iam list-roles --query 'Roles[].RoleName' --output text 2>/dev/null | tr '\t' '\n')
    
    # 并行处理角色
    for role in $roles_list; do
        if [ -n "$role" ] && [ "$role" != "None" ]; then
            wait_for_jobs "$MAX_PARALLEL_JOBS"
            process_iam_role "$role"
            ((checked_roles++))
        fi
    done
    
    # 等待所有角色处理完成
    wait
    
    echo "开始并行检查IAM用户..."
    
    # 获取所有用户列表
    local users_list=$(aws iam list-users --query 'Users[].UserName' --output text 2>/dev/null | tr '\t' '\n')
    
    # 并行处理用户
    for user in $users_list; do
        if [ -n "$user" ] && [ "$user" != "None" ]; then
            wait_for_jobs "$MAX_PARALLEL_JOBS"
            process_iam_user "$user"
            ((checked_users++))
        fi
    done
    
    # 等待所有用户处理完成
    wait
    
    echo "开始并行检查独立的客户管理策略..."
    
    # 获取所有客户管理策略列表
    local policies_list=$(aws iam list-policies --scope Local --query 'Policies[].Arn' --output text 2>/dev/null | tr '\t' '\n')
    
    # 并行处理独立策略
    for policy_arn in $policies_list; do
        if [ -n "$policy_arn" ] && [ "$policy_arn" != "None" ]; then
            wait_for_jobs "$MAX_PARALLEL_JOBS"
            process_standalone_policy "$policy_arn"
            ((customer_managed_policies++))
        fi
    done
    
    # 等待所有策略处理完成
    wait
    
    echo "IAM检查完成: 角色($checked_roles), 用户($checked_users), 客户管理策略($customer_managed_policies)"
    safe_log "IAM检查完成: 角色($checked_roles), 用户($checked_users), 客户管理策略($customer_managed_policies)" "$LOG_FILE"
}

# 2. 检查S3存储桶策略
check_s3_policies() {
    echo -e "${BLUE}2. 检查S3存储桶策略${NC}"
    update_check_count
    
    local checked_buckets=0
    
    while read -r bucket; do
        if [ -n "$bucket" ]; then
            ((checked_buckets++))
            log_check_detail "S3" "Bucket:$bucket" "检查中" "检查存储桶策略"
            
            bucket_policy=$(aws s3api get-bucket-policy --bucket "$bucket" --query 'Policy' --output text 2>/dev/null || echo "")
            if [ -n "$bucket_policy" ] && [ "$bucket_policy" != "None" ]; then
                if check_org_keywords "$bucket_policy"; then
                    log_issue "S3" "Bucket:$bucket" "存储桶策略包含组织相关配置" "$bucket_policy"
                    log_check_detail "S3" "Bucket:$bucket" "有问题" "存储桶策略包含组织相关配置"
                    log_org_finding "S3 Bucket Policy" "$bucket" "$bucket_policy"
                else
                    log_check_detail "S3" "Bucket:$bucket" "正常" "存储桶策略无组织相关配置"
                fi
            else
                log_check_detail "S3" "Bucket:$bucket" "无策略" "存储桶无策略配置"
            fi
        fi
    done < <(aws s3api list-buckets --query 'Buckets[].Name' --output text 2>/dev/null | tr '\t' '\n')
    
    echo "S3检查完成: 存储桶($checked_buckets)"
    safe_log "S3检查完成: 存储桶($checked_buckets)" "$LOG_FILE"
}

# 3. 检查KMS密钥策略
check_kms_policies() {
    echo -e "${BLUE}3. 检查KMS密钥策略${NC}"
    update_check_count
    
    local checked_keys=0
    
    while read -r key_id; do
        if [ -n "$key_id" ]; then
            ((checked_keys++))
            log_check_detail "KMS" "Key:$key_id" "检查中" "检查密钥策略"
            
            key_policy=$(aws kms get-key-policy --key-id "$key_id" --policy-name default --query 'Policy' --output text 2>/dev/null || echo "")
            if [ -n "$key_policy" ] && [ "$key_policy" != "None" ]; then
                if check_org_keywords "$key_policy"; then
                    log_issue "KMS" "Key:$key_id" "密钥策略包含组织相关配置" "$key_policy"
                    log_check_detail "KMS" "Key:$key_id" "有问题" "密钥策略包含组织相关配置"
                    log_org_finding "KMS Key Policy" "$key_id" "$key_policy"
                else
                    log_check_detail "KMS" "Key:$key_id" "正常" "密钥策略无组织相关配置"
                fi
            else
                log_check_detail "KMS" "Key:$key_id" "无策略" "密钥无策略配置"
            fi
        fi
    done < <(aws kms list-keys --query 'Keys[].KeyId' --output text 2>/dev/null | tr '\t' '\n')
    
    echo "KMS检查完成: 密钥($checked_keys)"
    safe_log "KMS检查完成: 密钥($checked_keys)" "$LOG_FILE"
}

# 4. 检查Lambda函数资源策略
check_lambda_policies() {
    echo -e "${BLUE}4. 检查Lambda函数资源策略${NC}"
    update_check_count
    
    local checked_functions=0
    
    while read -r function_name; do
        if [ -n "$function_name" ]; then
            ((checked_functions++))
            log_check_detail "Lambda" "Function:$function_name" "检查中" "检查函数资源策略"
            
            function_policy=$(aws lambda get-policy --function-name "$function_name" --query 'Policy' --output text 2>/dev/null || echo "")
            if [ -n "$function_policy" ] && [ "$function_policy" != "None" ]; then
                if check_org_keywords "$function_policy"; then
                    log_issue "Lambda" "Function:$function_name" "函数策略包含组织相关配置" "$function_policy"
                    log_check_detail "Lambda" "Function:$function_name" "有问题" "函数策略包含组织相关配置"
                    log_org_finding "Lambda Function Policy" "$function_name" "$function_policy"
                else
                    log_check_detail "Lambda" "Function:$function_name" "正常" "函数策略无组织相关配置"
                fi
            else
                log_check_detail "Lambda" "Function:$function_name" "无策略" "函数无资源策略"
            fi
        fi
    done < <(aws lambda list-functions --query 'Functions[].FunctionName' --output text 2>/dev/null | tr '\t' '\n')
    
    echo "Lambda检查完成: 函数($checked_functions)"
    safe_log "Lambda检查完成: 函数($checked_functions)" "$LOG_FILE"
}

# 5. 检查SNS主题策略
check_sns_policies() {
    echo -e "${BLUE}5. 检查SNS主题策略${NC}"
    update_check_count
    
    local checked_topics=0
    
    while read -r topic_arn; do
        if [ -n "$topic_arn" ]; then
            ((checked_topics++))
            log_check_detail "SNS" "Topic:$topic_arn" "检查中" "检查主题策略"
            
            topic_policy=$(aws sns get-topic-attributes --topic-arn "$topic_arn" --query 'Attributes.Policy' --output text 2>/dev/null || echo "")
            if [ -n "$topic_policy" ] && [ "$topic_policy" != "None" ]; then
                if check_org_keywords "$topic_policy"; then
                    log_issue "SNS" "Topic:$topic_arn" "主题策略包含组织相关配置" "$topic_policy"
                    log_check_detail "SNS" "Topic:$topic_arn" "有问题" "主题策略包含组织相关配置"
                    log_org_finding "SNS Topic Policy" "$topic_arn" "$topic_policy"
                else
                    log_check_detail "SNS" "Topic:$topic_arn" "正常" "主题策略无组织相关配置"
                fi
            else
                log_check_detail "SNS" "Topic:$topic_arn" "无策略" "主题无策略配置"
            fi
        fi
    done < <(aws sns list-topics --query 'Topics[].TopicArn' --output text 2>/dev/null | tr '\t' '\n')
    
    echo "SNS检查完成: 主题($checked_topics)"
    safe_log "SNS检查完成: 主题($checked_topics)" "$LOG_FILE"
}

# 6. 检查SQS队列策略
check_sqs_policies() {
    echo -e "${BLUE}6. 检查SQS队列策略${NC}"
    update_check_count
    
    local checked_queues=0
    
    while read -r queue_url; do
        if [ -n "$queue_url" ]; then
            ((checked_queues++))
            log_check_detail "SQS" "Queue:$queue_url" "检查中" "检查队列策略"
            
            queue_policy=$(aws sqs get-queue-attributes --queue-url "$queue_url" --attribute-names Policy --query 'Attributes.Policy' --output text 2>/dev/null || echo "")
            if [ -n "$queue_policy" ] && [ "$queue_policy" != "None" ]; then
                if check_org_keywords "$queue_policy"; then
                    log_issue "SQS" "Queue:$queue_url" "队列策略包含组织相关配置" "$queue_policy"
                    log_check_detail "SQS" "Queue:$queue_url" "有问题" "队列策略包含组织相关配置"
                    log_org_finding "SQS Queue Policy" "$queue_url" "$queue_policy"
                else
                    log_check_detail "SQS" "Queue:$queue_url" "正常" "队列策略无组织相关配置"
                fi
            else
                log_check_detail "SQS" "Queue:$queue_url" "无策略" "队列无策略配置"
            fi
        fi
    done < <(aws sqs list-queues --query 'QueueUrls[]' --output text 2>/dev/null | tr '\t' '\n')
    
    echo "SQS检查完成: 队列($checked_queues)"
    safe_log "SQS检查完成: 队列($checked_queues)" "$LOG_FILE"
}

# ========================================
# 主执行流程
# ========================================

echo -e "${YELLOW}开始检查各服务策略 (优化版本)...${NC}"
safe_log "开始检查各服务策略 (优化版本) - $(date)" "$LOG_FILE"
echo ""

# 记录开始时间
start_time=$(date +%s)

# 执行所有检查函数
# 注释掉不需要的检查项目即可跳过
check_iam_policies_optimized
check_s3_policies
check_kms_policies
check_lambda_policies
check_sns_policies
check_sqs_policies

# 记录结束时间
end_time=$(date +%s)
duration=$((end_time - start_time))

echo ""
echo -e "${GREEN}=== 检查完成 ===${NC}"
echo "检查耗时: ${duration}秒"
safe_log "检查完成 - $(date), 耗时: ${duration}秒" "$LOG_FILE"

# 显示总结
total_checks=$(jq -r '.summary.total_checks' "$ISSUES_FILE")
issues_found=$(jq -r '.summary.issues_found' "$ISSUES_FILE")

echo "总检查项目: $total_checks"
echo "发现问题: $issues_found"
safe_log "总检查项目: $total_checks, 发现问题: $issues_found" "$LOG_FILE"

# 检查组织相关发现文件的内容
org_findings_count=$(grep -c "^[A-Z].*:" "$ORG_FINDINGS_FILE" 2>/dev/null || echo "0")

if [ "$issues_found" -gt 0 ]; then
    echo -e "${RED}发现 $issues_found 个与组织相关的策略配置问题${NC}"
    echo "详细信息请查看:"
    echo "- 主日志文件: $LOG_FILE"
    echo "- 详细日志文件: $DETAILED_LOG_FILE"
    echo "- JSON报告: $ISSUES_FILE"
    echo -e "${YELLOW}- 组织相关发现详情: $ORG_FINDINGS_FILE${NC}"
    echo ""
    echo -e "${YELLOW}建议在迁移账号前修复这些问题${NC}"
    
    # 按服务分组显示问题摘要
    echo ""
    echo -e "${YELLOW}问题摘要:${NC}"
    jq -r '.issues | group_by(.service) | .[] | "\(.[0].service): \(length) 个问题"' "$ISSUES_FILE" | while read -r line; do
        echo "  - $line"
    done
    
    # 显示组织相关发现的摘要
    if [ "$org_findings_count" -gt 0 ]; then
        echo ""
        echo -e "${YELLOW}组织相关发现摘要:${NC}"
        echo "  - 共发现 $org_findings_count 个包含组织相关配置的资源"
        echo "  - 详细策略内容已保存到: $ORG_FINDINGS_FILE"
    fi
else
    echo -e "${GREEN}未发现组织相关的策略配置问题${NC}"
    echo -e "${GREEN}账号可以安全迁移${NC}"
fi

echo ""
echo "检查完成时间: $(date)"
echo "检查耗时: ${duration}秒"
safe_log "检查完成时间: $(date), 耗时: ${duration}秒" "$LOG_FILE"
echo ""
echo "文件输出位置:"
echo "- 主日志: $LOG_FILE"
echo "- 详细日志: $DETAILED_LOG_FILE"
echo "- JSON报告: $ISSUES_FILE"
if [ "$org_findings_count" -gt 0 ]; then
    echo -e "${YELLOW}- 组织相关发现: $ORG_FINDINGS_FILE (包含 $org_findings_count 个发现)${NC}"
else
    echo "- 组织相关发现: $ORG_FINDINGS_FILE (无发现)"
fi

# 在组织相关发现文件末尾添加总结
echo "" >> "$ORG_FINDINGS_FILE"
echo "========================================" >> "$ORG_FINDINGS_FILE"
echo "检查总结:" >> "$ORG_FINDINGS_FILE"
echo "- 检查完成时间: $(date)" >> "$ORG_FINDINGS_FILE"
echo "- 检查耗时: ${duration}秒" >> "$ORG_FINDINGS_FILE"
echo "- 总检查项目: $total_checks" >> "$ORG_FINDINGS_FILE"
echo "- 发现问题: $issues_found" >> "$ORG_FINDINGS_FILE"
echo "- 组织相关发现: $org_findings_count" >> "$ORG_FINDINGS_FILE"

# 清理临时文件
rm -rf "$TEMP_DIR"
