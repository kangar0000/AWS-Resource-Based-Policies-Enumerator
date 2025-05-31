import boto3
import botocore
import os
import sys
import configparser
import json
from botocore.exceptions import ClientError, NoCredentialsError, ProfileNotFound

PROFILE = "default"

def safe_call(client, func, **kwargs):
    try:
        return getattr(client, func)(**kwargs)
    except ClientError as e:
        code = e.response['Error']['Code']
        if code in ['AccessDeniedException', 'AccessDenied', 'UnauthorizedOperation', 'AuthorizationError', 'Client.UnauthorizedOperation']:
            return {"__error__": "ACCESS_DENIED", "message": str(e)}
        elif code in ['NoSuchBucketPolicy', 'ResourceNotFoundException', 'PolicyNotFound']:
            return {"__error__": "NO_POLICY"}
        else:
            return {"__error__": "ERROR", "message": str(e)}
    except Exception as e:
        return {"__error__": "ERROR", "message": str(e)}

def handle_policy_result(service, resource, result):
    if isinstance(result, dict) and "__error__" in result:
        error_type = result["__error__"]
        if error_type == "ACCESS_DENIED":
            print(f"[{service.upper()}] {resource} [ACCESS DENIED]")
        elif error_type == "NO_POLICY":
            print(f"[{service.upper()}] {resource} [NO POLICY]")
        else:
            print(f"[{service.upper()}] {resource} [ERROR] {result['message']}")
        return False
    return True

def print_json_policy(service, resource, policy):
    print(f"\n[{service.upper()}] {resource}")
    try:
        parsed = json.loads(policy)
        print(json.dumps(parsed, indent=2))
    except Exception:
        print(policy)

def print_dict_policy(service, resource, policy_dict):
    print(f"\n[{service.upper()}] {resource}")
    print(json.dumps(policy_dict, indent=2))

def print_error(context, error_msg):
    print(f"[ERROR] {context}: {error_msg}\n")

def prompt_profile_selection():
    config_path = os.path.expanduser("~/.aws/config")
    creds_path = os.path.expanduser("~/.aws/credentials")
    config = configparser.ConfigParser()
    profiles = set()

    for path in [config_path, creds_path]:
        if os.path.exists(path):
            config.read(path)
            for section in config.sections():
                profile = section.replace("profile ", "") if section.startswith("profile ") else section
                profiles.add(profile)

    profiles = sorted(profiles)
    print("\nAvailable AWS profiles:")
    for i, profile in enumerate(profiles, 1):
        print(f"{i}. {profile}")
    choice = input("\nEnter profile name or number (default = default): ").strip()
    if choice == "":
        return "default"
    if choice.isdigit() and 1 <= int(choice) <= len(profiles):
        return profiles[int(choice)-1]
    if choice in profiles:
        return choice
    print("Invalid profile selection.")
    sys.exit(1)

def prompt_service_selection(service_map):
    print("\n=== AWS Resource-Based Policy Enumerator ===")
    print("Type AWS services to scan (comma-separated) or 'all' to scan all supported.")
    print("Supported services:", ", ".join(sorted(service_map)))
    choice = input("\nYour choice: ").strip().lower()
    if choice == "all":
        return list(service_map.keys())
    selected = [s.strip() for s in choice.split(",")]
    invalid = [s for s in selected if s not in service_map]
    if invalid:
        print("Invalid services:", ", ".join(invalid))
        sys.exit(1)
    return selected

def get_client(service):
    return boto3.Session(profile_name=PROFILE).client(service)

# === Service-Specific Enumerators ===

def get_s3_policies():
    client = get_client("s3")
    result = safe_call(client, "list_buckets")
    if result and "Buckets" in result:
        for b in result["Buckets"]:
            name = b["Name"]
            policy = safe_call(client, "get_bucket_policy", Bucket=name)
            if handle_policy_result("S3", f"Bucket: {name}", policy):
                print_json_policy("S3", f"Bucket: {name}", policy["Policy"])

def get_lambda_policies():
    client = get_client("lambda")
    funcs = safe_call(client, "list_functions")
    if funcs and "Functions" in funcs:
        for f in funcs["Functions"]:
            name = f["FunctionName"]
            policy = safe_call(client, "get_policy", FunctionName=name)
            if handle_policy_result("Lambda", f"Function: {name}", policy):
                print_json_policy("Lambda", f"Function: {name}", policy["Policy"])

def get_kms_policies():
    client = get_client("kms")
    keys = safe_call(client, "list_keys")
    if keys and "Keys" in keys:
        for k in keys["Keys"]:
            key_id = k["KeyId"]
            policy = safe_call(client, "get_key_policy", KeyId=key_id, PolicyName="default")
            if handle_policy_result("KMS", f"Key ID: {key_id}", policy):
                print_json_policy("KMS", f"Key ID: {key_id}", policy["Policy"])

def get_iam_role_trust_policies():
    client = get_client("iam")
    roles = safe_call(client, "list_roles")
    if roles and "Roles" in roles:
        for role in roles["Roles"]:
            name = role["RoleName"]
            trust = role.get("AssumeRolePolicyDocument")
            if trust:
                print_dict_policy("IAM", f"Role: {name} Trust Policy", trust)

def get_eventbridge_policies():
    client = get_client("events")
    buses = safe_call(client, "list_event_buses")
    if buses and "EventBuses" in buses:
        for bus in buses["EventBuses"]:
            name = bus["Name"]
            desc = safe_call(client, "describe_event_bus", Name=name)
            if handle_policy_result("EventBridge", f"Bus: {name}", desc):
                if "Policy" in desc:
                    print_json_policy("EventBridge", f"Bus: {name}", desc["Policy"])

def get_secretsmanager_policies():
    client = get_client("secretsmanager")
    secrets = safe_call(client, "list_secrets")
    if secrets and "SecretList" in secrets:
        for s in secrets["SecretList"]:
            arn = s["ARN"]
            policy = safe_call(client, "get_resource_policy", SecretId=arn)
            if handle_policy_result("SecretsManager", f"Secret: {arn}", policy):
                if "ResourcePolicy" in policy:
                    print_json_policy("SecretsManager", f"Secret: {arn}", policy["ResourcePolicy"])

def get_sns_policies():
    client = get_client("sns")
    topics = safe_call(client, "list_topics")
    if topics and "Topics" in topics:
        for topic in topics["Topics"]:
            arn = topic["TopicArn"]
            attrs = safe_call(client, "get_topic_attributes", TopicArn=arn)
            if handle_policy_result("SNS", f"Topic: {arn}", attrs):
                if "Attributes" in attrs and "Policy" in attrs["Attributes"]:
                    print_json_policy("SNS", f"Topic: {arn}", attrs["Attributes"]["Policy"])

def get_sqs_policies():
    client = get_client("sqs")
    queues = safe_call(client, "list_queues")
    if queues and "QueueUrls" in queues:
        for url in queues["QueueUrls"]:
            attrs = safe_call(client, "get_queue_attributes", QueueUrl=url, AttributeNames=["Policy"])
            if handle_policy_result("SQS", f"Queue: {url}", attrs):
                if "Attributes" in attrs and "Policy" in attrs["Attributes"]:
                    print_json_policy("SQS", f"Queue: {url}", attrs["Attributes"]["Policy"])

# === Map of supported services to functions ===

SERVICE_MAP = {
    "s3": get_s3_policies,
    "lambda": get_lambda_policies,
    "kms": get_kms_policies,
    "iam": get_iam_role_trust_policies,
    "eventbridge": get_eventbridge_policies,
    "secretsmanager": get_secretsmanager_policies,
    "sns": get_sns_policies,
    "sqs": get_sqs_policies,
}

# === Main logic ===

def main():
    global PROFILE
    try:
        PROFILE = prompt_profile_selection()
        selected_services = prompt_service_selection(SERVICE_MAP)
        print(f"\nUsing profile: {PROFILE}")
        print("\n" + "="*60)
        print("   AWS Resource-Based Policy Enumeration")
        print("="*60)
        for service in selected_services:
            print(f"\n--- {service.upper()} ---")
            try:
                SERVICE_MAP[service]()
            except Exception as e:
                print_error(service.upper(), str(e))
        print("\n" + "="*60)
        print("   Enumeration Complete")
        print("="*60)
    except ProfileNotFound:
        print_error("Profile", f"AWS profile '{PROFILE}' not found.")
    except NoCredentialsError:
        print_error("Credentials", "AWS credentials not found. Run `aws configure`.")

if __name__ == "__main__":
    main()
