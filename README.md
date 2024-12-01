# Aws-Roles-Enum
**IAM Policy Checker**

An AWS IAM Policy Checker script to help users 
audit their AWS IAM policies, identify potential security risks, 
and highlight permissions that could lead to privilege escalation. 
This tool is designed to assist in securing AWS environments by making 
it easier to understand the permissions granted to IAM users.

# Table of Contents

    Features
    Requirements
    Installation
    Usage
        Basic Usage
        Specify an AWS Profile
        Check for a Specific Command or Action
    Examples
    Customization
    Contributing
    License

# Features

  Audit IAM User Policies: Lists all managed and inline policies attached to the current IAM user.
  Highlight Potentially Sensitive Actions: Scans policies for actions that are considered sensitive and could lead to privilege escalation.
  Visual Indicators: Highlights matched actions in color for easy identification.
  Customizable Action List: Allows users to define their own list of actions to search for.
  Supports AWS Profiles: Can use different AWS profiles configured in your AWS credentials file.

# Requirements

    Python 3.6 or higher
    boto3 library
    AWS credentials configured (either via environment variables or AWS credentials file)

**# Installation**

  # Clone the Repository

    git clone https://github.com/yourusername/iam-policy-checker.git
    cd iam-policy-checker

  # Install Dependencies

  It's recommended to use a virtual environment:

    python3 -m venv venv
    source venv/bin/activate  # On Windows use: venv\Scripts\activate
    pip install boto3

# Usage

      python iam_policy_checker.py [options]

  **Basic Usage**
  Run the script without any options to audit the current IAM user's policies:

    python iam_policy_checker.py

  **Specify an AWS Profile**
   If you have multiple AWS profiles configured, you can specify which one to use:

    python iam_policy_checker.py --profile your_profile_name

  **Check for a Specific Command or Action**
    You can check if a specific AWS command or action exists in your attached policies:

    python iam_policy_checker.py --command s3:PutObject


# Examples

  **Audit Current IAM User Policies**

    python iam_policy_checker.py

  **Sample Output:**

    Current IAM User: alice
    Attached Policies (2):
     - arn:aws:iam::123456789012:policy/ReadOnlyAccess
     - Inline Policy: CustomPolicy
    
    Managed Policy arn:aws:iam::123456789012:policy/ReadOnlyAccess contains the following statements:
    Effect: Allow
    Resources:
      - *
    Actions:
      - ec2:DescribeInstances
      - s3:ListBucket
    
    Inline Policy CustomPolicy contains the following statements:
    Effect: Allow
    Resources:
      - *
    Actions:
      - iam:CreateUser      # Highlighted in red
      - iam:DeleteUser      # Highlighted in red
      - s3:PutObject
    
  **Check for a Specific Action**

    python iam_policy_checker.py --command iam:DeleteUser

  **Sample Output:**

    Current IAM User: alice
    Attached Policies (2):
     - arn:aws:iam::123456789012:policy/ReadOnlyAccess
     - Inline Policy: CustomPolicy

    Inline Policy CustomPolicy contains the following statements:
    Effect: Allow
    Resources:
      - *
    Actions:
      - iam:CreateUser
      - iam:DeleteUser      # Highlighted in green
      - s3:PutObject

    The command/action 'iam:DeleteUser' exists in one or more attached policies.

# Customization
  Modify the List of Sensitive Actions

  The script contains a predefined list of actions (actions_to_search) 
  that are considered sensitive. You can modify this list to suit your needs.

  **Example:**

    actions_to_search = [
        "iam:CreateUser",
        "iam:DeleteUser",
        "s3:PutObject",
        # Add or remove actions as needed
    ]

  **Change Highlight Colors**

  The script uses ANSI escape codes to highlight matching actions. 
  You can customize the colors by modifying the ANSI codes at the top of the script.

  **Example:**
  
    # Define ANSI color codes
    RESET = "\033[0m"
    BOLD = "\033[1m"
    GREEN = "\033[32m"  # Change to "\033[34m" for blue
    RED = "\033[31m"
    
# License

  This project is licensed under the GNU General Public License v3.0 (GPLv3) License. 
  See the LICENSE file for details.

# Disclaimer 
  
  **This tool is intended for educational and security auditing purposes within your own AWS environments. 
  Always ensure you have the appropriate permissions before running security assessment tools. 
  Unauthorized access or use of systems is prohibited.
**  
