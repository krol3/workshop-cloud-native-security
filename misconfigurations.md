
# Detecting Misconfigurations


[![owasp-5](https://techdocs.f5.com/dam/f5/kb/global/solutions/k10622005_images/A6_security_misconfiguration.png)](https://support.f5.com/csp/article/K10622005)

## Table of Contents
- [Prerequisites](#prerequisites)
- [Misconfigurations in Container Images](#misconfigurations-in-container-images)
- [Misconfigurations in Kubernetes](#misconfigurations-in-kubernetes)
- [Misconfigurations in Infra as Code](#misconfigurations-in-infra-as-code)
- [CI Integration](#ci-integration)

## Prerequisites

Before you begin, you need the following software:

- A Linux, stand-alone virtual machine (VM)
- [Trivy](https://www.aquasec.com/products/trivy/) command-line tool. [Installation steps here](https://aquasecurity.github.io/trivy/v0.20.0/getting-started/installation/)
- [Tfsec](https://github.com/aquasecurity/tfsec) command-line tool. [Installation steps here](https://github.com/aquasecurity/tfsec#installation)

## Misconfigurations in Container Images

`trivy config  .`

<details>
<summary>Show results</summary>

![](https://i.imgur.com/2SYJEQe.png)
</details></br>

Sample repository used [here](https://github.com/krol3/infra-code-tf).
## Misconfigurations in Kubernetes

`trivy config  .`

<details>
<summary>Show results</summary>

![](https://i.imgur.com/cZ2NagX.png)

</details></br>

## Misconfigurations in Infra as Code

**Using tfsec in Terraform manifests**

`tfsec .`

<details>
<summary>Show results</summary>

```
WARNING: Failed to load module: missing module with source 'terraform-aws-modules/security-group/aws' -  try to 'terraform init' first
WARNING: Failed to load module: missing module with source 'terraform-aws-modules/ec2-instance/aws' -  try to 'terraform init' first
WARNING: Failed to load module: missing module with source 'terraform-aws-modules/s3-bucket/aws' -  try to 'terraform init' first

  Result 1

  [aws-kms-auto-rotate-keys][MEDIUM] Resource 'aws_kms_key.this' does not have KMS Key auto-rotation enabled.
  /Users/krol/workspace/github/infra-code-tf/app-ec2/main.tf:79-80


      76 |   tags = local.tags
      77 | }
      78 |
      79 | resource "aws_kms_key" "this" {
      80 | }
      81 |
      82 | resource "aws_network_interface" "this" {
      83 |   count = 1

  Legacy ID:  AWS019
  Impact:     Long life KMS keys increase the attack surface when compromised
  Resolution: Configure KMS key to auto rotate

  More Info:
  - https://tfsec.dev/docs/aws/kms/auto-rotate-keys#aws/kms
  - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/kms_key#enable_key_rotation
  - https://docs.aws.amazon.com/kms/latest/developerguide/rotate-keys.html

  times
  ------------------------------------------
  disk i/o             31.415294ms
  parsing HCL          27.395µs
  evaluating values    427.268µs
  running checks       2.329946ms

  counts
  ------------------------------------------
  files loaded         7
  blocks               21
  modules              0

  results
  ------------------------------------------
  critical             0
  high                 0
  medium               1
  low                  0
  ignored              0

  1 potential problems detected.
```

</details></br>
<br>

**Using trivy**

`trivy conf .`

<details>
<summary>Show results</summary>

```
WARNING: Failed to load module: missing module with source 'terraform-aws-modules/security-group/aws' -  try to 'terraform init' first
WARNING: Failed to load module: missing module with source 'terraform-aws-modules/ec2-instance/aws' -  try to 'terraform init' first
WARNING: Failed to load module: missing module with source 'terraform-aws-modules/s3-bucket/aws' -  try to 'terraform init' first
2021-10-27T22:44:28.692-0300	INFO	Detected config files: 4

app-ec2/main.tf (terraform)
===========================
Tests: 14 (SUCCESSES: 13, FAILURES: 1, EXCEPTIONS: 0)
Failures: 1 (UNKNOWN: 0, LOW: 0, MEDIUM: 1, HIGH: 0, CRITICAL: 0)

+------------------------------------------+--------------+------------------------------------------+----------+----------------------------------------------------+
|                   TYPE                   |  MISCONF ID  |                  CHECK                   | SEVERITY |                      MESSAGE                       |
+------------------------------------------+--------------+------------------------------------------+----------+----------------------------------------------------+
|   Terraform Security Check powered by    | AVD-AWS-0065 | A KMS key is not configured to           |  MEDIUM  | Resource 'aws_kms_key.this' does not               |
|                  tfsec                   |              | auto-rotate.                             |          | have KMS Key auto-rotation enabled.                |
|                                          |              |                                          |          | -->tfsec.dev/docs/aws/kms/auto-rotate-keys#aws/kms |
+------------------------------------------+--------------+------------------------------------------+----------+----------------------------------------------------+

app-ec2/variables.tf (terraform)
================================
Tests: 8 (SUCCESSES: 8, FAILURES: 0, EXCEPTIONS: 0)
Failures: 0 (UNKNOWN: 0, LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0)


site-s3/main.tf (terraform)
===========================
Tests: 5 (SUCCESSES: 5, FAILURES: 0, EXCEPTIONS: 0)
Failures: 0 (UNKNOWN: 0, LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0)


site-s3/variables.tf (terraform)
================================
Tests: 2 (SUCCESSES: 2, FAILURES: 0, EXCEPTIONS: 0)
Failures: 0 (UNKNOWN: 0, LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0)
```
</details></br>
<br>

## CI Integration

Tfsec Sarif Result

![](https://i.imgur.com/V26WdZ1.png)


Trivy Result

![](https://i.imgur.com/MPgHSij.png)


Tfsec PR Commenter Result
    
![](https://i.imgur.com/7ZVOhcU.png)   

More details about [Trivy vs Tfsec](https://aquasecurity.github.io/trivy/dev/misconfiguration/comparison/tfsec/)

Sample repository [here](https://github.com/krol3/infra-code-tf). 
---
