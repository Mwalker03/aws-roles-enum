#!/usr/bin/env python3

import boto3
import json
import argparse
from botocore.exceptions import ClientError
import sys

# Define ANSI color codes
RESET = "\033[0m"
BOLD = "\033[1m"
GREEN = "\033[32m"
RED = "\033[31m"

def initialize_iam_client(profile):
    if profile:
        try:
            session = boto3.Session(profile_name=profile)
            iam_client = session.client('iam')
            return iam_client
        except Exception as e:
            print(f"Error initializing boto3 session with profile '{profile}': {e}")
            exit(1)
    else:
        return boto3.client('iam')

def get_current_user(iam_client):
    try:
        response = iam_client.get_user()
        user_name = response['User']['UserName']
        return user_name
    except ClientError as e:
        print(f"Error retrieving current user: {e}")
        exit(1)

def list_attached_policies(iam_client, user_name):
    try:
        paginator = iam_client.get_paginator('list_attached_user_policies')
        policy_arns = []
        for page in paginator.paginate(UserName=user_name):
            for policy in page['AttachedPolicies']:
                policy_arns.append(policy['PolicyArn'])
        # Also include inline policies
        inline_policies = iam_client.list_user_policies(UserName=user_name)['PolicyNames']
        for policy_name in inline_policies:
            policy_arns.append({'PolicyName': policy_name, 'IsInline': True})
        return policy_arns
    except ClientError as e:
        print(f"Error listing attached policies for user {user_name}: {e}")
        exit(1)

def get_latest_policy_version(iam_client, policy_arn):
    try:
        policy = iam_client.get_policy(PolicyArn=policy_arn)
        version_id = policy['Policy']['DefaultVersionId']
        policy_version = iam_client.get_policy_version(
            PolicyArn=policy_arn,
            VersionId=version_id
        )
        return policy_version['PolicyVersion']['Document']
    except ClientError as e:
        print(f"Error retrieving policy version for {policy_arn}: {e}")
        return None

def get_inline_policy_document(iam_client, user_name, policy_name):
    try:
        policy_document = iam_client.get_user_policy(
            UserName=user_name,
            PolicyName=policy_name
        )['PolicyDocument']
        return policy_document
    except ClientError as e:
        print(f"Error retrieving inline policy {policy_name} for user {user_name}: {e}")
        return None

def process_policy_document(policy_document, actions_to_search):
    results = []
    statements = policy_document.get('Statement', [])
    
    # Normalize statements to a list
    if isinstance(statements, dict):
        statements = [statements]
    
    for statement in statements:
        actions = statement.get('Action', [])
        resources = statement.get('Resource', [])
        effect = statement.get('Effect', '')
        
        # Normalize actions and resources to lists
        if isinstance(actions, str):
            actions = [actions]
        if isinstance(resources, str):
            resources = [resources]
        
        action_details = []
        for action in actions:
            is_match = False
            # Check for exact match or wildcard match
            if action in actions_to_search:
                is_match = True
            else:
                for search_action in actions_to_search:
                    if search_action.endswith('*'):
                        prefix = search_action.rstrip('*')
                        if action.startswith(prefix):
                            is_match = True
                            break
            action_details.append({'action': action, 'is_match': is_match})
        
        results.append({
            'effect': effect,
            'resources': resources,
            'actions': action_details
        })
    
    return results

def main(command_to_check=None, profile=None):
    iam_client = initialize_iam_client(profile)
    
    # Step 1: Get current user name
    user_name = get_current_user(iam_client)
    print(f"{BOLD}Current IAM User:{RESET} {user_name}")
    
    # Step 2: List attached policies
    policy_arns = list_attached_policies(iam_client, user_name)
    print(f"{BOLD}Attached Policies ({len(policy_arns)}):{RESET}")
    for policy in policy_arns:
        if isinstance(policy, dict) and policy.get('IsInline'):
            print(f" - Inline Policy: {policy['PolicyName']}")
        else:
            print(f" - {policy}")
    
    # Step 3: Define actions to search for
    actions_to_search = [
        "PutKeyPolicy",
        "secretsmanager:ListSecrets",
        "iam:CreatePolicyVersion",
        "iam:SetDefaultPolicyVersion",
        "iam:CreateAccessKey",
        "iam:CreateLoginProfile",
        "iam:UpdateLoginProfile",
        "iam:UpdateAccessKey",
        "iam:CreateServiceSpecificCredential",
        "iam:ResetServiceSpecificCredential",
        "iam:AttachUserPolicy",
        "iam:AttachGroupPolicy",
        "iam:AttachRolePolicy",
        "iam:createrole",
        "iam:PutUserPolicy",
        "iam:PutGroupPolicy",
        "iam:PutRolePolicy",
        "iam:AddUserToGroup",
        "iam:UpdateAssumeRolePolicy",
        "iam:UploadSSHPublicKey",
        "iam:DeactivateMFADevice",
        "iam:ResyncMFADevice",
        "iam:UpdateSAMLProvider",
        "iam:ListSAMLProviders",
        "iam:GetSAMLProvider",
        "iam:PassRole",
        
        "ec2:RunInstances",
        "ec2:AssociateIamInstanceProfile",
        "ec2:DisassociateIamInstanceProfile",
        "ec2:ReplaceIamInstanceProfileAssociation",
        "ec2:RequestSpotInstances",
        "ec2:ModifyInstanceAttribute",
        "ec2:CreateLaunchTemplateVersion",
        "ec2:CreateLaunchTemplate",
        "ec2:ModifyLaunchTemplate",
        "ec2:describe-launch-templates",
        "ec2:describe-launch-template-versions",
        "ec2:UpdateSecurityGroupRuleDescriptionsIngress",
        "ec2:UpdateSecurityGroupRuleDescriptionsEgress",
        "ec2:RevokeSecurityGroupIngress",
        "ec2:RevokeSecurityGroupEgress",
        "ec2:ModifySecurityGroupRules",
        "ec2:DescribeSecurityGroups",
        "ec2:AuthorizeSecurityGroupIngress",
        "ec2:AuthorizeSecurityGroupEgress",
        "ec2:List*",
        "ec2:Describe*",
        "autoscaling:CreateLaunchConfiguration",
        "autoscaling:CreateAutoScalingGroup",
        "ec2-instance-connect:SendSSHPublicKey",
        "ec2-instance-connect:SendSerialConsoleSSHPublicKey",
        "ssm:SendCommand",
        "lightsail:DownloadDefaultKeyPair",
        "lightsail:GetInstanceAccessDetails",
        "lightsail:CreateBucketAccessKey",
        "lightsail:GetRelationalDatabaseMasterUserPassword",
        "lightsail:UpdateRelationalDatabase",
        "lightsail:OpenInstancePublicPorts",
        "lightsail:PutInstancePublicPorts",
        "lightsail:SetResourceAccessForBucket",
        "lightsail:UpdateBucket",
        "lightsail:UpdateContainerService",
        "lightsail:CreateDomainEntry",
        "lightsail:UpdateDomainEntry",
        "lambda:CreateFunction",
        "lambda:InvokeFunction",
        "lambda:InvokeFunctionUrl",
        "lambda:AddPermission",
        "lambda:CreateEventSourceMapping",
        "lambda:AddLayerVersionPermission",
        "lambda:GetLayerVersion",
        "lambda:UpdateFunctionCode",
        "lambda:UpdateFunctionConfiguration",
        "dynamodb:PutItem",
        "dynamodb:CreateTable",
        # Add more actions as needed
    ]
    
    if command_to_check:
        actions_to_search.append(command_to_check)
    
    # Step 4: Iterate through each policy and process actions
    action_found = False
    for policy in policy_arns:
        if isinstance(policy, dict) and policy.get('IsInline'):
            # Handle inline policies
            policy_name = policy['PolicyName']
            policy_document = get_inline_policy_document(iam_client, user_name, policy_name)
            policy_identifier = f"Inline Policy {policy_name}"
        else:
            policy_arn = policy
            policy_document = get_latest_policy_version(iam_client, policy_arn)
            policy_identifier = f"Managed Policy {policy_arn}"
        
        if not policy_document:
            continue
        
        # Process the policy document to get all actions and mark matches
        processed_statements = process_policy_document(policy_document, actions_to_search)
        
        print(f"\n{BOLD}{policy_identifier} contains the following statements:{RESET}")
        for stmt in processed_statements:
            print(f"{BOLD}Effect:{RESET} {stmt['effect']}")
            print(f"{BOLD}Resources:{RESET}")
            for resource in stmt['resources']:
                print(f"  - {resource}")
            print(f"{BOLD}Actions:{RESET}")
            for action_detail in stmt['actions']:
                action = action_detail['action']
                is_match = action_detail['is_match']
                if is_match:
                    # Highlight matching actions in green
                    print(f"  - {BOLD}{RED}{action}{RESET}")
                    action_found = True
                else:
                    print(f"  - {action}")
            print()
    
    # Step 5: Report based on the command_to_check
    if command_to_check:
        if action_found:
            print(f"\n{BOLD}{GREEN}The command/action '{command_to_check}' exists in one or more attached policies.{RESET}")
        else:
            print(f"\n{BOLD}{RED}The command/action '{command_to_check}' does NOT exist in any attached policies.{RESET}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="AWS IAM Policy Checker",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Example Usage:
  python iam_policy_checker.py --command ssm:SendCommand --profile admin
  python iam_policy_checker.py -c iam:DeleteUser -p dev_profile
        """
    )
    
    parser.add_argument(
        "-c", "--command",
        type=str,
        help="Specify a command/action to check its existence in attached policies."
    )
    
    parser.add_argument(
        "-p", "--profile",
        type=str,
        default=None,
        help="Specify the AWS profile to use from the AWS credentials file."
    )
    
    args = parser.parse_args()
    
    main(command_to_check=args.command, profile=args.profile)
