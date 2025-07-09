#!/usr/bin/env python3
"""
AWS账号组织策略检查工具 - Python版本
用于检查账号中所有服务的策略是否包含组织相关配置
支持并发执行以提高性能
"""

import os
import sys
import json
import re
import time
import logging
import argparse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
import boto3
from botocore.exceptions import ClientError, NoCredentialsError
import colorama
from colorama import Fore, Style

# 初始化colorama
colorama.init()

class OrgPolicyChecker:
    """AWS组织策略检查器"""
    
    def __init__(self, max_workers=None, debug=False):
        """
        初始化检查器
        
        Args:
            max_workers: 最大并发数
            debug: 是否启用调试模式
        """
        self.debug = debug
        self.setup_logging()
        
        # 检测环境并设置默认并发数
        self.max_workers = self._determine_max_workers(max_workers)
        
        # 初始化AWS客户端
        self.session = boto3.Session()
        self._init_aws_clients()
        
        # 线程安全锁
        self.lock = Lock()
        
        # 结果存储
        self.issues = []
        self.check_details = []
        self.org_findings = []
        
        # 统计信息
        self.total_checks = 0
        self.issues_found = 0
        
        # 组织相关关键词
        self.org_keywords = [
            "aws:PrincipalOrgID",
            "aws:PrincipalOrgPaths", 
            "aws:ResourceOrgID",
            "aws:ResourceOrgPaths",
            "aws:SourceOrgID",
            "aws:SourceOrgPaths",
            "organizations:",
            r"\bo-[a-z0-9]{10}",
            r"\bou-[a-z0-9]+-[a-z0-9]{8}"
        ]
        
        # 创建输出目录和文件
        self._setup_output_files()
    
    def _determine_max_workers(self, max_workers):
        """根据环境确定最大并发数"""
        if max_workers:
            return max_workers
            
        # 检测CloudShell环境
        if os.getenv('AWS_EXECUTION_ENV') and 'CloudShell' in os.getenv('AWS_EXECUTION_ENV', ''):
            self.logger.info("检测到CloudShell环境，使用优化配置")
            return 8
        else:
            return 15
    
    def setup_logging(self):
        """设置日志"""
        level = logging.DEBUG if self.debug else logging.INFO
        logging.basicConfig(
            level=level,
            format='%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        self.logger = logging.getLogger(__name__)
    
    def _init_aws_clients(self):
        """初始化AWS客户端"""
        try:
            # 验证AWS凭证
            sts = self.session.client('sts')
            identity = sts.get_caller_identity()
            self.account_id = identity['Account']
            self.logger.info(f"AWS账号ID: {self.account_id}")
            
            # 初始化各服务客户端
            self.iam = self.session.client('iam')
            self.s3 = self.session.client('s3')
            self.kms = self.session.client('kms')
            self.lambda_client = self.session.client('lambda')
            self.sns = self.session.client('sns')
            self.sqs = self.session.client('sqs')
            
        except NoCredentialsError:
            self.logger.error("AWS凭证未配置")
            sys.exit(1)
        except Exception as e:
            self.logger.error(f"初始化AWS客户端失败: {e}")
            sys.exit(1)
    
    def _setup_output_files(self):
        """设置输出文件"""
        # 创建logs目录
        os.makedirs('logs', exist_ok=True)
        
        # 生成时间戳
        timestamp = datetime.now().strftime('%Y%m%d-%H%M%S')
        
        # 定义文件路径
        self.log_file = f'logs/org-policy-check-python-{timestamp}.log'
        self.detailed_log_file = f'logs/org-policy-detailed-python-{timestamp}.log'
        self.issues_file = f'logs/org-policy-issues-python-{timestamp}.json'
        self.findings_file = f'logs/org-policy-findings-python-{timestamp}.txt'
        
        # 初始化文件
        self._init_output_files()
    
    def _init_output_files(self):
        """初始化输出文件"""
        # 初始化JSON报告文件
        initial_data = {
            "issues": [],
            "summary": {"total_checks": 0, "issues_found": 0},
            "check_details": []
        }
        with open(self.issues_file, 'w', encoding='utf-8') as f:
            json.dump(initial_data, f, indent=2, ensure_ascii=False)
        
        # 初始化组织相关发现文件
        with open(self.findings_file, 'w', encoding='utf-8') as f:
            f.write("AWS账号组织策略检查 - 组织相关发现 (Python版本)\n")
            f.write(f"检查时间: {datetime.now()}\n")
            f.write("=" * 50 + "\n\n")
    
    def check_org_keywords(self, content):
        """检查内容是否包含组织相关关键词"""
        if not content:
            return False
            
        content_str = json.dumps(content) if isinstance(content, dict) else str(content)
        
        for keyword in self.org_keywords:
            if re.search(keyword, content_str, re.IGNORECASE):
                return True
        return False
    
    def log_issue(self, service, resource, issue, details=""):
        """记录问题"""
        with self.lock:
            print(f"{Fore.RED}[问题] {service} - {resource}: {issue}{Style.RESET_ALL}")
            
            issue_data = {
                "service": service,
                "resource": resource,
                "issue": issue,
                "details": str(details)
            }
            self.issues.append(issue_data)
            self.issues_found += 1
    
    def log_check_detail(self, service, resource, status, message):
        """记录详细检查信息"""
        with self.lock:
            detail_data = {
                "service": service,
                "resource": resource,
                "status": status,
                "message": message,
                "timestamp": datetime.now().isoformat()
            }
            self.check_details.append(detail_data)
            
            if self.debug:
                print(f"[{service}] {resource}: {status} - {message}")
    
    def log_org_finding(self, finding_type, resource_name, policy_content):
        """记录组织相关发现"""
        with self.lock:
            finding = {
                "type": finding_type,
                "resource": resource_name,
                "policy": policy_content
            }
            self.org_findings.append(finding)
    
    def update_check_count(self):
        """更新检查计数"""
        with self.lock:
            self.total_checks += 1
    
    def process_iam_role(self, role_name):
        """处理单个IAM角色"""
        try:
            self.log_check_detail("IAM", f"Role:{role_name}", "检查中", "检查角色信任策略")
            
            # 获取角色信任策略
            try:
                response = self.iam.get_role(RoleName=role_name)
                trust_policy = response['Role']['AssumeRolePolicyDocument']
                
                if self.check_org_keywords(trust_policy):
                    self.log_issue("IAM", f"Role:{role_name}", "信任策略包含组织相关配置", trust_policy)
                    self.log_check_detail("IAM", f"Role:{role_name}", "有问题", "信任策略包含组织相关配置")
                    self.log_org_finding("Role Trust Policy", role_name, trust_policy)
                else:
                    self.log_check_detail("IAM", f"Role:{role_name}", "正常", "信任策略无组织相关配置")
                    
            except ClientError as e:
                self.log_check_detail("IAM", f"Role:{role_name}", "错误", f"获取角色信任策略失败: {e}")
            
            # 检查附加的客户管理策略
            try:
                response = self.iam.list_attached_role_policies(RoleName=role_name)
                for policy in response['AttachedPolicies']:
                    policy_arn = policy['PolicyArn']
                    
                    # 只检查客户管理的策略
                    if not policy_arn.startswith('arn:aws:iam::aws:policy'):
                        self._check_customer_managed_policy(policy_arn, f"attached to role: {role_name}")
                        
            except ClientError as e:
                self.log_check_detail("IAM", f"Role:{role_name}", "错误", f"获取角色附加策略失败: {e}")
                
        except Exception as e:
            self.log_check_detail("IAM", f"Role:{role_name}", "错误", f"处理角色时发生异常: {e}")
    
    def process_iam_user(self, user_name):
        """处理单个IAM用户"""
        try:
            self.log_check_detail("IAM", f"User:{user_name}", "检查中", "检查用户附加的客户管理策略")
            
            # 检查附加的客户管理策略
            try:
                response = self.iam.list_attached_user_policies(UserName=user_name)
                for policy in response['AttachedPolicies']:
                    policy_arn = policy['PolicyArn']
                    
                    # 只检查客户管理的策略
                    if not policy_arn.startswith('arn:aws:iam::aws:policy'):
                        self._check_customer_managed_policy(policy_arn, f"attached to user: {user_name}")
                        
            except ClientError as e:
                self.log_check_detail("IAM", f"User:{user_name}", "错误", f"获取用户附加策略失败: {e}")
                
        except Exception as e:
            self.log_check_detail("IAM", f"User:{user_name}", "错误", f"处理用户时发生异常: {e}")
    
    def process_standalone_policy(self, policy_arn):
        """处理独立的客户管理策略"""
        try:
            self.log_check_detail("IAM", f"StandalonePolicy:{policy_arn}", "检查中", "检查独立的客户管理策略")
            self._check_customer_managed_policy(policy_arn, "standalone")
        except Exception as e:
            self.log_check_detail("IAM", f"StandalonePolicy:{policy_arn}", "错误", f"处理独立策略时发生异常: {e}")
    
    def _check_customer_managed_policy(self, policy_arn, context=""):
        """检查客户管理策略内容"""
        try:
            # 获取策略版本
            policy_response = self.iam.get_policy(PolicyArn=policy_arn)
            version_id = policy_response['Policy']['DefaultVersionId']
            
            # 获取策略内容
            version_response = self.iam.get_policy_version(
                PolicyArn=policy_arn,
                VersionId=version_id
            )
            policy_document = version_response['PolicyVersion']['Document']
            
            if self.check_org_keywords(policy_document):
                self.log_issue("IAM", f"Policy:{policy_arn}", "客户管理策略包含组织相关配置", policy_document)
                self.log_check_detail("IAM", f"Policy:{policy_arn}", "有问题", "客户管理策略包含组织相关配置")
                self.log_org_finding("Customer Managed Policy", f"{policy_arn} ({context})", policy_document)
            else:
                self.log_check_detail("IAM", f"Policy:{policy_arn}", "正常", "客户管理策略无组织相关配置")
                
        except ClientError as e:
            self.log_check_detail("IAM", f"Policy:{policy_arn}", "错误", f"获取策略内容失败: {e}")
    
    def check_iam_policies(self):
        """检查IAM策略 - 并发执行"""
        print(f"{Fore.BLUE}1. 检查IAM策略 (仅客户管理策略) - 并发处理{Style.RESET_ALL}")
        self.update_check_count()
        
        # 获取所有角色
        print("开始并发检查IAM角色...")
        try:
            paginator = self.iam.get_paginator('list_roles')
            roles = []
            for page in paginator.paginate():
                roles.extend([role['RoleName'] for role in page['Roles']])
            
            print(f"发现 {len(roles)} 个IAM角色")
            
            # 并发处理角色
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                futures = [executor.submit(self.process_iam_role, role) for role in roles]
                
                completed = 0
                for future in as_completed(futures):
                    completed += 1
                    if completed % 10 == 0:
                        print(f"已完成 {completed}/{len(roles)} 个角色的检查")
                    
                    try:
                        future.result()
                    except Exception as e:
                        self.logger.error(f"角色检查异常: {e}")
            
            print(f"完成 {len(roles)} 个角色的处理")
            
        except Exception as e:
            self.logger.error(f"获取IAM角色列表失败: {e}")
        
        # 获取所有用户
        print("开始并发检查IAM用户...")
        try:
            paginator = self.iam.get_paginator('list_users')
            users = []
            for page in paginator.paginate():
                users.extend([user['UserName'] for user in page['Users']])
            
            print(f"发现 {len(users)} 个IAM用户")
            
            # 并发处理用户
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                futures = [executor.submit(self.process_iam_user, user) for user in users]
                
                completed = 0
                for future in as_completed(futures):
                    completed += 1
                    if completed % 10 == 0:
                        print(f"已完成 {completed}/{len(users)} 个用户的检查")
                    
                    try:
                        future.result()
                    except Exception as e:
                        self.logger.error(f"用户检查异常: {e}")
            
            print(f"完成 {len(users)} 个用户的处理")
            
        except Exception as e:
            self.logger.error(f"获取IAM用户列表失败: {e}")
        
        # 获取所有客户管理策略
        print("开始并发检查独立的客户管理策略...")
        try:
            paginator = self.iam.get_paginator('list_policies')
            policies = []
            for page in paginator.paginate(Scope='Local'):
                policies.extend([policy['Arn'] for policy in page['Policies']])
            
            print(f"发现 {len(policies)} 个客户管理策略")
            
            # 并发处理策略
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                futures = [executor.submit(self.process_standalone_policy, policy) for policy in policies]
                
                completed = 0
                for future in as_completed(futures):
                    completed += 1
                    if completed % 10 == 0:
                        print(f"已完成 {completed}/{len(policies)} 个策略的检查")
                    
                    try:
                        future.result()
                    except Exception as e:
                        self.logger.error(f"策略检查异常: {e}")
            
            print(f"完成 {len(policies)} 个策略的处理")
            
        except Exception as e:
            self.logger.error(f"获取客户管理策略列表失败: {e}")
        
        print("IAM检查完成")
        self.logger.info("IAM检查完成")
    
    def check_s3_policies(self):
        """检查S3存储桶策略"""
        print(f"{Fore.BLUE}2. 检查S3存储桶策略{Style.RESET_ALL}")
        self.update_check_count()
        
        checked_buckets = 0
        
        try:
            response = self.s3.list_buckets()
            buckets = [bucket['Name'] for bucket in response['Buckets']]
            
            for bucket_name in buckets:
                checked_buckets += 1
                self.log_check_detail("S3", f"Bucket:{bucket_name}", "检查中", "检查存储桶策略")
                
                try:
                    policy_response = self.s3.get_bucket_policy(Bucket=bucket_name)
                    policy_document = json.loads(policy_response['Policy'])
                    
                    if self.check_org_keywords(policy_document):
                        self.log_issue("S3", f"Bucket:{bucket_name}", "存储桶策略包含组织相关配置", policy_document)
                        self.log_check_detail("S3", f"Bucket:{bucket_name}", "有问题", "存储桶策略包含组织相关配置")
                        self.log_org_finding("S3 Bucket Policy", bucket_name, policy_document)
                    else:
                        self.log_check_detail("S3", f"Bucket:{bucket_name}", "正常", "存储桶策略无组织相关配置")
                        
                except ClientError as e:
                    if e.response['Error']['Code'] == 'NoSuchBucketPolicy':
                        self.log_check_detail("S3", f"Bucket:{bucket_name}", "无策略", "存储桶无策略配置")
                    else:
                        self.log_check_detail("S3", f"Bucket:{bucket_name}", "错误", f"获取存储桶策略失败: {e}")
        
        except Exception as e:
            self.logger.error(f"检查S3策略失败: {e}")
        
        print(f"S3检查完成: 存储桶({checked_buckets})")
        self.logger.info(f"S3检查完成: 存储桶({checked_buckets})")
    
    def check_kms_policies(self):
        """检查KMS密钥策略"""
        print(f"{Fore.BLUE}3. 检查KMS密钥策略{Style.RESET_ALL}")
        self.update_check_count()
        
        checked_keys = 0
        
        try:
            paginator = self.kms.get_paginator('list_keys')
            
            for page in paginator.paginate():
                for key in page['Keys']:
                    key_id = key['KeyId']
                    checked_keys += 1
                    self.log_check_detail("KMS", f"Key:{key_id}", "检查中", "检查密钥策略")
                    
                    try:
                        response = self.kms.get_key_policy(KeyId=key_id, PolicyName='default')
                        policy_document = json.loads(response['Policy'])
                        
                        if self.check_org_keywords(policy_document):
                            self.log_issue("KMS", f"Key:{key_id}", "密钥策略包含组织相关配置", policy_document)
                            self.log_check_detail("KMS", f"Key:{key_id}", "有问题", "密钥策略包含组织相关配置")
                            self.log_org_finding("KMS Key Policy", key_id, policy_document)
                        else:
                            self.log_check_detail("KMS", f"Key:{key_id}", "正常", "密钥策略无组织相关配置")
                            
                    except ClientError as e:
                        self.log_check_detail("KMS", f"Key:{key_id}", "错误", f"获取密钥策略失败: {e}")
        
        except Exception as e:
            self.logger.error(f"检查KMS策略失败: {e}")
        
        print(f"KMS检查完成: 密钥({checked_keys})")
        self.logger.info(f"KMS检查完成: 密钥({checked_keys})")
    
    def check_lambda_policies(self):
        """检查Lambda函数资源策略"""
        print(f"{Fore.BLUE}4. 检查Lambda函数资源策略{Style.RESET_ALL}")
        self.update_check_count()
        
        checked_functions = 0
        
        try:
            paginator = self.lambda_client.get_paginator('list_functions')
            
            for page in paginator.paginate():
                for function in page['Functions']:
                    function_name = function['FunctionName']
                    checked_functions += 1
                    self.log_check_detail("Lambda", f"Function:{function_name}", "检查中", "检查函数资源策略")
                    
                    try:
                        response = self.lambda_client.get_policy(FunctionName=function_name)
                        policy_document = json.loads(response['Policy'])
                        
                        if self.check_org_keywords(policy_document):
                            self.log_issue("Lambda", f"Function:{function_name}", "函数策略包含组织相关配置", policy_document)
                            self.log_check_detail("Lambda", f"Function:{function_name}", "有问题", "函数策略包含组织相关配置")
                            self.log_org_finding("Lambda Function Policy", function_name, policy_document)
                        else:
                            self.log_check_detail("Lambda", f"Function:{function_name}", "正常", "函数策略无组织相关配置")
                            
                    except ClientError as e:
                        if e.response['Error']['Code'] == 'ResourceNotFoundException':
                            self.log_check_detail("Lambda", f"Function:{function_name}", "无策略", "函数无资源策略")
                        else:
                            self.log_check_detail("Lambda", f"Function:{function_name}", "错误", f"获取函数策略失败: {e}")
        
        except Exception as e:
            self.logger.error(f"检查Lambda策略失败: {e}")
        
        print(f"Lambda检查完成: 函数({checked_functions})")
        self.logger.info(f"Lambda检查完成: 函数({checked_functions})")
    
    def save_results(self):
        """保存检查结果"""
        # 保存JSON报告
        report_data = {
            "issues": self.issues,
            "summary": {
                "total_checks": self.total_checks,
                "issues_found": self.issues_found
            },
            "check_details": self.check_details
        }
        
        with open(self.issues_file, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)
        
        # 保存组织相关发现
        if self.org_findings:
            with open(self.findings_file, 'a', encoding='utf-8') as f:
                for finding in self.org_findings:
                    f.write(f"{finding['type']}: {finding['resource']}\n")
                    f.write(f"Policy Content: {json.dumps(finding['policy'], indent=2, ensure_ascii=False)}\n")
                    f.write("---\n")
        
        # 添加总结
        with open(self.findings_file, 'a', encoding='utf-8') as f:
            f.write("\n" + "=" * 50 + "\n")
            f.write("检查总结:\n")
            f.write(f"- 检查完成时间: {datetime.now()}\n")
            f.write(f"- 总检查项目: {self.total_checks}\n")
            f.write(f"- 发现问题: {self.issues_found}\n")
            f.write(f"- 组织相关发现: {len(self.org_findings)}\n")
    
    def run_checks(self):
        """运行所有检查"""
        print(f"{Fore.BLUE}=== AWS账号组织策略检查工具 (Python版本) ==={Style.RESET_ALL}")
        print(f"最大并发数: {self.max_workers}")
        print(f"问题报告: {self.issues_file}")
        print(f"组织相关发现: {self.findings_file}")
        print()
        
        start_time = time.time()
        
        print(f"{Fore.YELLOW}开始检查各服务策略...{Style.RESET_ALL}")
        print()
        
        # 执行各项检查
        self.check_iam_policies()
        self.check_s3_policies()
        self.check_kms_policies()
        self.check_lambda_policies()
        
        end_time = time.time()
        duration = int(end_time - start_time)
        
        print()
        print(f"{Fore.GREEN}=== 检查完成 ==={Style.RESET_ALL}")
        print(f"检查耗时: {duration}秒")
        
        # 保存结果
        self.save_results()
        
        # 显示总结
        print(f"总检查项目: {self.total_checks}")
        print(f"发现问题: {self.issues_found}")
        
        org_findings_count = len(self.org_findings)
        
        if self.issues_found > 0:
            print(f"{Fore.RED}发现 {self.issues_found} 个与组织相关的策略配置问题{Style.RESET_ALL}")
            print("详细信息请查看:")
            print(f"- JSON报告: {self.issues_file}")
            print(f"{Fore.YELLOW}- 组织相关发现详情: {self.findings_file}{Style.RESET_ALL}")
            
            if org_findings_count > 0:
                print()
                print(f"{Fore.YELLOW}组织相关发现摘要:{Style.RESET_ALL}")
                print(f"  - 共发现 {org_findings_count} 个包含组织相关配置的资源")
                print(f"  - 详细策略内容已保存到: {self.findings_file}")
        else:
            print(f"{Fore.GREEN}未发现组织相关的策略配置问题{Style.RESET_ALL}")
            print(f"{Fore.GREEN}账号可以安全迁移{Style.RESET_ALL}")
        
        print()
        print(f"检查完成时间: {datetime.now()}")
        print(f"检查耗时: {duration}秒")
        print()
        print("文件输出位置:")
        print(f"- JSON报告: {self.issues_file}")
        if org_findings_count > 0:
            print(f"{Fore.YELLOW}- 组织相关发现: {self.findings_file} (包含 {org_findings_count} 个发现){Style.RESET_ALL}")
        else:
            print(f"- 组织相关发现: {self.findings_file} (无发现)")


def main():
    """主函数"""
    parser = argparse.ArgumentParser(description='AWS账号组织策略检查工具 (Python版本)')
    parser.add_argument('--max-workers', type=int, help='最大并发数')
    parser.add_argument('--debug', action='store_true', help='启用调试模式')
    
    args = parser.parse_args()
    
    # 从环境变量获取配置
    max_workers = args.max_workers or int(os.getenv('MAX_PARALLEL_JOBS', 10)) or None
    debug = args.debug or os.getenv('DEBUG') == '1'
    
    try:
        checker = OrgPolicyChecker(max_workers=max_workers, debug=debug)
        checker.run_checks()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}检查被用户中断{Style.RESET_ALL}")
        sys.exit(1)
    except Exception as e:
        print(f"{Fore.RED}检查过程中发生错误: {e}{Style.RESET_ALL}")
        sys.exit(1)


if __name__ == '__main__':
    main()
