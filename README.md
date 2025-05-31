# 🔍 AWS Resource-Based Policy Enumerator

A Python-based tool to **automatically enumerate resource-based IAM policies** across AWS services.  
Created to fill a gap I noticed during cloud enumeration workflow where I over looked resource-based policies were often overlooked.
This script was built with prompt engineering :)

> ⚠️ **Work in progress:** New services and formats are continuously being added as use cases arise.

---

## 🚀 Features

Enumerates **resource-based IAM policies** from commonly targeted AWS services, current script includes:

- **Amazon S3** – Bucket Policies  
- **AWS Lambda** – Function Policies  
- **AWS KMS** – Key Policies  
- **Amazon SNS** – Topic Policies  
- **Amazon SQS** – Queue Policies  
- **AWS Secrets Manager** – Secret Policies  
- **Amazon EventBridge** – Event Bus Policies  
- **IAM Roles** – Trust Policies

---

## ⚙️ Installation

### 1. Clone the repository

```bash
git clone https://github.com/kangar0000/AWS-Resource-Based-Policies-Enumerator.git
cd aws-resource-policy-enumerator
```

### 2. Ensure Python 3 and pip are installed

This tool requires **Python 3.6 or later** and `pip`.

You can check your versions with:

```bash
python3 --version
pip3 --version
```

If either is missing, install Python from [https://www.python.org/downloads/](https://www.python.org/downloads/)

---

### 3. Install dependencies

This script uses the `boto3` library to interact with AWS services.

Install it using:

```bash
pip3 install boto3
```

You're now ready to run the enumerator!
