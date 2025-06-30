#!/usr/bin/env python3
"""
AWS账号组织策略检查工具
用于检查账号中所有服务的策略是否包含组织相关配置
"""

import boto3
import json
import re
import sys
from datetime import datetime
from typing import List, Dict, Any
import argparse

class OrgPolicyChecker:
    def __init__(self, profile_name=None, region='us-east-1'):
        """初始化AWS客户端"""
        self.session = boto3.Session(profile_name=profile_name)
        self.region = region
        self.issues = []
        self.total_checks = 0
        
        # 组织相关关键词
        self.org_keywords = [
            r'aws:PrincipalOrgID',
            r'aws:PrincipalOrgPaths',
            r'aws:RequestedRegion',
            r'organizations:',
            r'o-[a-z0-9]{10}',  # 组织ID格式
            r'ou-[a-z0-9]+-[a-z0-9]{8}',  # 组织单元ID格式
            r'r-[a-z0-9]{4}',  # 根ID格式
        ]
        
    def check_org_keywords(self, content: str) -> List[str]:
        """检查内容中是否包含组织相关关键词"""
        if not content:
            return []
        
        found_keywords = []
        for keyword in self.org_keywords:
            if re.search(keyword, content, re.IGNORECASE):
                found_keywords.append(keyword)
        return found_keywords
    
    def log_issue(self, service: str, resource: str, issue: str, details: str, keywords: List[str]):
        """记录发现的问题"""
        self.issues.append({
            'service': service,
            'resource': resource,
            'issue': issue,
            'details': details,
            'keywords_found': keywords,
            'timestamp': datetime.now().isoformat()
        })
        print(f"❌ [{service}] {resource}: {issue}")
    
    def check_iam_policies(self):
        """检查IAM策略"""
        print("🔍 检查IAM策略...")
        iam = self.session.client('iam', region_name=self.region)
        self.total_checks += 1
        
        try:
            # 检查IAM角色
            roles = iam.list_roles()['Roles']
            for role in roles:
                role_name = role['RoleName']
                
                # 检查信任策略
                trust_policy = json.dumps(role['AssumeRolePolicyDocument'])
                keywords = self.check_org_keywords(trust_policy)
                if keywords:
                    self.log_issue('IAM', f'Role:{role_name}', '信任策略包含组织相关配置', trust_policy, keywords)
                
                # 检查附加的托管策略
                try:
                    attached_policies = iam.list_attached_role_policies(RoleName=role_name)['AttachedPolicies']
                    for policy in attached_policies:
                        policy_arn = policy['PolicyArn']
                        if policy_arn.startswith('arn:aws:iam::aws:policy/'):
                            continue  # 跳过AWS托管策略
                        
                        try:
                            policy_details = iam.get_policy(PolicyArn=policy_arn)
                            version_id = policy_details['Policy']['DefaultVersionId']
                            policy_version = iam.get_policy_version(PolicyArn=policy_arn, VersionId=version_id)
                            policy_content = json.dumps(policy_version['PolicyVersion']['Document'])
                            
                            keywords = self.check_org_keywords(policy_content)
                            if keywords:
                                self.log_issue('IAM', f'Policy:{policy_arn}', '策略包含组织相关配置', policy_content, keywords)
                        except Exception as e:
                            print(f"⚠️  无法检查策略 {policy_arn}: {e}")
                except Exception as e:
                    print(f"⚠️  无法检查角色 {role_name} 的附加策略: {e}")
            
            # 检查IAM用户
            users = iam.list_users()['Users']
            for user in users:
                user_name = user['UserName']
                try:
                    attached_policies = iam.list_attached_user_policies(UserName=user_name)['AttachedPolicies']
                    for policy in attached_policies:
                        policy_arn = policy['PolicyArn']
                        if policy_arn.startswith('arn:aws:iam::aws:policy/'):
                            continue  # 跳过AWS托管策略
                        
                        try:
                            policy_details = iam.get_policy(PolicyArn=policy_arn)
                            version_id = policy_details['Policy']['DefaultVersionId']
                            policy_version = iam.get_policy_version(PolicyArn=policy_arn, VersionId=version_id)
                            policy_content = json.dumps(policy_version['PolicyVersion']['Document'])
                            
                            keywords = self.check_org_keywords(policy_content)
                            if keywords:
                                self.log_issue('IAM', f'UserPolicy:{user_name}->{policy_arn}', '用户策略包含组织相关配置', policy_content, keywords)
                        except Exception as e:
                            print(f"⚠️  无法检查策略 {policy_arn}: {e}")
                except Exception as e:
                    print(f"⚠️  无法检查用户 {user_name} 的附加策略: {e}")
                    
        except Exception as e:
            print(f"❌ 检查IAM策略时出错: {e}")
    
    def check_s3_policies(self):
        """检查S3存储桶策略"""
        print("🔍 检查S3存储桶策略...")
        s3 = self.session.client('s3', region_name=self.region)
        self.total_checks += 1
        
        try:
            buckets = s3.list_buckets()['Buckets']
            for bucket in buckets:
                bucket_name = bucket['Name']
                try:
                    bucket_policy = s3.get_bucket_policy(Bucket=bucket_name)['Policy']
                    keywords = self.check_org_keywords(bucket_policy)
                    if keywords:
                        self.log_issue('S3', f'Bucket:{bucket_name}', '存储桶策略包含组织相关配置', bucket_policy, keywords)
                except s3.exceptions.NoSuchBucketPolicy:
                    pass  # 没有策略是正常的
                except Exception as e:
                    print(f"⚠️  无法检查存储桶 {bucket_name} 的策略: {e}")
        except Exception as e:
            print(f"❌ 检查S3策略时出错: {e}")
    
    def check_kms_policies(self):
        """检查KMS密钥策略"""
        print("🔍 检查KMS密钥策略...")
        kms = self.session.client('kms', region_name=self.region)
        self.total_checks += 1
        
        try:
            keys = kms.list_keys()['Keys']
            for key in keys:
                key_id = key['KeyId']
                try:
                    key_policy = kms.get_key_policy(KeyId=key_id, PolicyName='default')['Policy']
                    keywords = self.check_org_keywords(key_policy)
                    if keywords:
                        self.log_issue('KMS', f'Key:{key_id}', '密钥策略包含组织相关配置', key_policy, keywords)
                except Exception as e:
                    print(f"⚠️  无法检查密钥 {key_id} 的策略: {e}")
        except Exception as e:
            print(f"❌ 检查KMS策略时出错: {e}")
    
    def check_lambda_policies(self):
        """检查Lambda函数资源策略"""
        print("🔍 检查Lambda函数资源策略...")
        lambda_client = self.session.client('lambda', region_name=self.region)
        self.total_checks += 1
        
        try:
            functions = lambda_client.list_functions()['Functions']
            for function in functions:
                function_name = function['FunctionName']
                try:
                    function_policy = lambda_client.get_policy(FunctionName=function_name)['Policy']
                    keywords = self.check_org_keywords(function_policy)
                    if keywords:
                        self.log_issue('Lambda', f'Function:{function_name}', '函数策略包含组织相关配置', function_policy, keywords)
                except lambda_client.exceptions.ResourceNotFoundException:
                    pass  # 没有策略是正常的
                except Exception as e:
                    print(f"⚠️  无法检查函数 {function_name} 的策略: {e}")
        except Exception as e:
            print(f"❌ 检查Lambda策略时出错: {e}")
    
    def check_sns_policies(self):
        """检查SNS主题策略"""
        print("🔍 检查SNS主题策略...")
        sns = self.session.client('sns', region_name=self.region)
        self.total_checks += 1
        
        try:
            topics = sns.list_topics()['Topics']
            for topic in topics:
                topic_arn = topic['TopicArn']
                try:
                    attributes = sns.get_topic_attributes(TopicArn=topic_arn)['Attributes']
                    if 'Policy' in attributes:
                        topic_policy = attributes['Policy']
                        keywords = self.check_org_keywords(topic_policy)
                        if keywords:
                            self.log_issue('SNS', f'Topic:{topic_arn}', '主题策略包含组织相关配置', topic_policy, keywords)
                except Exception as e:
                    print(f"⚠️  无法检查主题 {topic_arn} 的策略: {e}")
        except Exception as e:
            print(f"❌ 检查SNS策略时出错: {e}")
    
    def check_sqs_policies(self):
        """检查SQS队列策略"""
        print("🔍 检查SQS队列策略...")
        sqs = self.session.client('sqs', region_name=self.region)
        self.total_checks += 1
        
        try:
            queues = sqs.list_queues()
            if 'QueueUrls' in queues:
                for queue_url in queues['QueueUrls']:
                    try:
                        attributes = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=['Policy'])['Attributes']
                        if 'Policy' in attributes:
                            queue_policy = attributes['Policy']
                            keywords = self.check_org_keywords(queue_policy)
                            if keywords:
                                self.log_issue('SQS', f'Queue:{queue_url}', '队列策略包含组织相关配置', queue_policy, keywords)
                    except Exception as e:
                        print(f"⚠️  无法检查队列 {queue_url} 的策略: {e}")
        except Exception as e:
            print(f"❌ 检查SQS策略时出错: {e}")
    
    def run_all_checks(self):
        """运行所有检查"""
        print("🚀 开始AWS账号组织策略检查...")
        print(f"检查时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 50)
        
        # 运行所有检查
        self.check_iam_policies()
        self.check_s3_policies()
        self.check_kms_policies()
        self.check_lambda_policies()
        self.check_sns_policies()
        self.check_sqs_policies()
        
        # 生成报告
        self.generate_report()
    
    def generate_report(self):
        """生成检查报告"""
        print("\n" + "=" * 50)
        print("📊 检查结果总结")
        print("=" * 50)
        
        print(f"总检查项目: {self.total_checks}")
        print(f"发现问题: {len(self.issues)}")
        
        if self.issues:
            print(f"\n❌ 发现 {len(self.issues)} 个与组织相关的策略配置问题:")
            
            # 按服务分组显示问题
            service_issues = {}
            for issue in self.issues:
                service = issue['service']
                if service not in service_issues:
                    service_issues[service] = []
                service_issues[service].append(issue)
            
            for service, issues in service_issues.items():
                print(f"\n🔸 {service} ({len(issues)} 个问题):")
                for issue in issues:
                    print(f"  - {issue['resource']}: {issue['issue']}")
                    print(f"    关键词: {', '.join(issue['keywords_found'])}")
            
            # 保存详细报告
            timestamp = datetime.now().strftime('%Y%m%d-%H%M%S')
            report_file = f"org-policy-issues-{timestamp}.json"
            
            report = {
                'summary': {
                    'total_checks': self.total_checks,
                    'issues_found': len(self.issues),
                    'check_time': datetime.now().isoformat()
                },
                'issues': self.issues
            }
            
            with open(report_file, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            
            print(f"\n📄 详细报告已保存到: {report_file}")
            print("⚠️  建议在迁移账号前修复这些问题")
            
        else:
            print("\n✅ 未发现组织相关的策略配置问题")
            print("✅ 账号可以安全迁移")
        
        print(f"\n检查完成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

def main():
    parser = argparse.ArgumentParser(description='AWS账号组织策略检查工具')
    parser.add_argument('--profile', help='AWS配置文件名称')
    parser.add_argument('--region', default='us-east-1', help='AWS区域 (默认: us-east-1)')
    
    args = parser.parse_args()
    
    try:
        checker = OrgPolicyChecker(profile_name=args.profile, region=args.region)
        checker.run_all_checks()
    except Exception as e:
        print(f"❌ 运行检查时出错: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
