# Deep Dive: AWS Organization Policies (Part 1\)

## Introduction

As organizations scale their cloud infrastructure, managing AWS accounts securely and efficiently becomes both a necessity and a challenge. Today, companies heavily rely on [AWS Organizations](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_introduction.html) or [AWS Control Tower](https://docs.aws.amazon.com/controltower/latest/userguide/what-is-control-tower.html) to manage their multi-account AWS environments and meet their business, governance, security, and operational goal. This strategy enables workload isolation, improved quota and resource management, and the enforcement of security controls across environments (development, testing, and production). However, managing AWS accounts at scale introduces complexities — maintaining governance, enforcing guardrails, and streamlining operations across the organization.

This is where [AWS Organization Policies](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies.html) play a pivotal role. These are rules that are applied at the organizational level for controlling resource access, enforcing security controls, and ensuring standardized configurations across multiple AWS accounts. They ensure that all accounts within an organization operate within these defined boundaries, thereby balancing flexibility with proper governance. There are 2 types of AWS Organization Policies:

- [**Authorization Policies**](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_authorization_policies.html): Authorization policies provide the ability to centrally define and enforce the maximum available permissions for principals and resources within your AWS Organizations. The two types of Authorization Policies are:  
      - **Service Control Policies (SCPs)**: SCPs allow you to centrally define and enforce maximum available permissions for principals (IAM users, root users, and roles) within your AWS Organizations.  
      - **Resource Control Policies (RCPs)**: RCPs allow you to centrally define and enforce the maximum available permissions for resources within your AWS Organizations.  

- [**Management Policies**](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_management_policies.html): Management policies provide the ability to centrally define and enforce configurations on services and resources within your AWS Organizations. The different types of Management Policies are:  
      - **Declarative Policies**: Declarative policies allow you to centrally define and enforce baseline configuration of resources within your AWS Organizations.  
      - **Backup Policies**: Backup policies allow you to centrally manage backups for resources within your AWS Organizations.  
      - **Tag Policies**: Tag policies allow you to centrally enforce tagging standards on resources within your AWS Organizations.  
      - **Chatbot Policies**: Chatbot policies allow you to centrally restrict access to resources within your AWS Organizations, from Teams, Slack, etc.  
      - **AI Services Opt-Out Policies**: AI policies allow you to centrally control access to your data and prevent them from being used in the development of AWS’ AI services.

In the remainder of this blog (Part 1), I will take a deep-dive into the two types of Authorization Policies: SCPs and RCPs. I will follow this with a subsequent blog (Part 2) that delves into the various types of Management Policies.

## Service Control Policies (SCPs)

[Service Control Policies (SCPs)](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html) are a type of authorization policy that provides you with centralized control over the maximum permissions that are available to the principals (IAM users, root users, roles) within your AWS Organization. By design, SCPs restrict permissions rather than grant them. Thus, they create permission guardrails and ensure that principals within your organizations operate within these predefined access boundaries. Below are key considerations when implementing SCPs:

### SCP Applicability Scope

- SCPs apply only to IAM principals managed by member accounts within your organization. They do not apply to IAM principals that reside outside your organization.
- SCPs do not apply to policies attached directly to resources (i.e., resource policies).  
      - For example, if an Amazon S3 bucket owned by account A has a bucket policy granting access to users in account B (outside the organization), the SCP attached to account A does not apply to those external users or the resource policies.
- SCPs do not apply to [service-linked roles](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create-service-linked-role.html).
- SCPs do not apply to IAM principals within the management account. However, they do apply to IAM principals within delegated admin accounts.
- SCPs do not apply to the following tasks/entities:
      - Register for the Enterprise support plan as the root user.
      - Provide trusted signer functionality for CloudFront private content.
      - Configure reverse DNS for an Amazon Lightsail email server and Amazon EC2 instance as the root user.
      - Tasks on some AWS-related services:
        - Alexa Top Sites.
        - Alexa Web Information Service.
        - Amazon Mechanical Turk.
        - Amazon Product Marketing API.

### SCP Permission Evaluation Logic

- SCPs operate on a deny-by-default model. If an action or service is not explicitly allowed by the SCP, it is implicitly denied, regardless of IAM permissions.
      - Hence, when SCPs are initially enabled, AWS attaches the [`FullAWSAccess`](https://console.aws.amazon.com/organizations/?#/policies/p-FullAWSAccess) policy at the root level of your organization. This ensures that all services and actions remain initially allowed until more restrictive policies are applied.
- The permissions available to principals within accounts are restricted by the SCPs applied at every level above it in the organization. If a specific permission is denied or not explicitly allowed at the parent level (root, OU, or the principal’s account), the action cannot be performed by the principal even if they have admin access.
- SCPs do not grant permissions; hence, IAM principals need to be assigned permissions explicitly via IAM policies.
      - **Example:** If access to a service (e.g., S3) is “Allowed” via SCPs but the principal does not have permissions assigned to it explicitly via IAM policies, the principal cannot access S3.
- If an IAM principal has an IAM policy that grants access to an action:
      - And the SCP also explicitly allows the action, then the principal can perform that action.
      - But if the SCP does not explicitly allow or deny the action, the principal cannot perform that action.
- If permissions boundaries are present, access must be allowed by all three mechanisms — SCPs, permission boundaries, and IAM policies - to perform the action.

The flowchart below provides a high-level overview of how access decisions are made when SCPs are enabled:

![Permissions Evaluation Logic - SCPs](images/Permissions%20Evaluation%20Logic%20-%20SCPs.png)

### SCP Development and Testing

- Use "Deny" statements to enforce baseline security controls that you want to apply across your entire organization.  
      - **Example**: Prevent member accounts from leaving your organization.

```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "DenyLeavingOrganization",
            "Effect": "Deny",
            "Action": [
                "organizations:LeaveOrganization"
            ],
            "Resource": "*"
        }
    ]
}
```

- Use "Deny" statements with conditions to manage exceptions or enforce certain specific controls.  
      - **Example**: Enforce the use of IMDSv2 for EC2 instances. 

```
{
	"Version": "2012-10-17",
	"Statement": [
		{
			"Sid": "DenyRunInstancesWithoutIMDSv2",
			"Effect": "Deny",
			"Action": "ec2:RunInstances",
			"Resource": "*",
			"Condition": {
				"StringNotEquals": {
					"ec2:MetadataHttpTokens": "required"
				}
			}
		},
		{
			"Sid": "DenyRunInstancesWithHighHopLimit",
			"Effect": "Deny",
			"Action": "ec2:RunInstances",
			"Resource": "*",
			"Condition": {
				"NumericGreaterThan": {
					"ec2:MetadataHttpPutResponseHopLimit": "3"
				}
			}
		},
		{
			"Sid": "DenyAllActionsForInsecureRoleDelivery",
			"Effect": "Deny",
			"Action": "*",
			"Resource": "*",
			"Condition": {
				"NumericLessThan": {
					"ec2:RoleDelivery": "2.0"
				}
			}
		},
		{
			"Sid": "DenyMetadataOptionsModificationForNonAdmins",
			"Effect": "Deny",
			"Action": "ec2:ModifyInstanceMetadataOptions",
			"Resource": "*",
			"Condition": {
				"StringNotLike": {
					"aws:PrincipalARN": "arn:aws:iam::*:role/ec2-imds-admins"
				}
			}
		}
	]
}
```
- **Example**: Prevent high-risk roles from changes except when made by whitelisted admin roles.

```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "DenyAccessWithException",
            "Effect": "Deny",
            "Action": [
                "iam:AttachRolePolicy",
                "iam:DeleteRole",
                "iam:DeleteRolePermissionsBoundary",
                "iam:DeleteRolePolicy",
                "iam:DetachRolePolicy",
                "iam:PutRolePermissionsBoundary",
                "iam:PutRolePolicy",
                "iam:UpdateAssumeRolePolicy",
                "iam:UpdateRole",
                "iam:UpdateRoleDescription"
            ],
            "Resource": [
                "arn:aws:iam::*:role/<role to protect from unauthorized changes>"
            ],
            "Condition": {
                "ArnNotLike": {
                    "aws:PrincipalARN": "arn:aws:iam::*:role/<approved admin that can make changes>"
                }
            }
        }
    ]
}
```

- By default, AWS applies the managed SCP `FullAWSAccess`, to all entities in the organization, which grants access to all services and actions. Be careful when removing this policy and not replacing it with another suitable policy (one that explicitly allows access to your desired list of services), as you can inadvertently end up locking yourself out.  
      - **Example**: Access should only be granted to approved services (S3, EC2, DynamoDB), and all other service access should be blocked. You can do this by applying the below SCP and removing the default `FullAWSAccess` policy.

```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AllowApprovedServiceAccess",
            "Effect": "Allow",
            "Action": [
                "s3:*",
                "ec2:*",
                "dynamodb:*",
                "organizations:*"
            ],
            "Resource": "*"
        }
    ]
}
```

- AWS currently does not have any features or mechanisms to run SCPs in audit-mode to monitor the behavior and ascertain that SCPs won’t inadvertently cause disruptions.  
      - Leverage [service last accessed data in IAM](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_access-advisor.html) to determine which services are in use versus not and then use this insight to develop SCPs.  
      - SCPs should be deployed to non-production accounts/OUs first to confirm they meet the requirements and are not causing disruptions. Once there’s reasonable assurance around the behavior of SCPs, only then extend the scope to production accounts/OUs.
      - Enable CloudTrail logging and query for access denied events where the failure reason is “service control policy.” Analyze the log entries to determine that all the denied events are intended and by design, and they are not blocking legitimate actions.
      - Never apply SCPs directly to the root OUs before thoroughly testing in lower/non-production accounts/OUs.          
- The blog post from AWS - [Get more out of service control policies in a multi-account environment](https://aws.amazon.com/blogs/security/get-more-out-of-service-control-policies-in-a-multi-account-environment/) - does a great job of walking through different approaches / recommendations for rolling out SCPs across multi-account environments, while staying within the limits and quotas of policy size (5120 characters), and number of SCPs (5) per entity (root, OUs, accounts). 

### SCP Reference Materials

Documentation, Blog Posts, and Videos:

- [AWS - Codify your best practices using service control policies: Part 1](https://aws.amazon.com/blogs/mt/codify-your-best-practices-using-service-control-policies-part-1/)  
- [AWS - Codify your best practices using service control policies: Part 2](https://aws.amazon.com/blogs/mt/codify-your-best-practices-using-service-control-policies-part-2/)  
- [AWS - How to use AWS Organizations to simplify security at enormous scale](https://aws.amazon.com/blogs/security/how-to-use-aws-organizations-to-simplify-security-at-enormous-scale/)  
- [AWS - Identity Guide – Preventive controls with AWS Identity – SCPs](https://aws.amazon.com/blogs/mt/identity-guide-preventive-controls-with-aws-identity-scps/)  
- [AWS - Best Practices for AWS Organizations Service Control Policies in a Multi-Account Environment](https://aws.amazon.com/blogs/industries/best-practices-for-aws-organizations-service-control-policies-in-a-multi-account-environment/)  
- [AWS - Control VPC sharing in an AWS multi-account setup with service control policies](https://aws.amazon.com/blogs/security/control-vpc-sharing-in-an-aws-multi-account-setup-with-service-control-policies/)
- [AWS re:Invent 2024 - Security invariants: From enterprise chaos to cloud order](https://www.youtube.com/watch?v=aljwG4N5a-0)
- [SummitRoute - AWS SCP Best Practices](https://summitroute.com/blog/2020/03/25/aws_scp_best_practices/#two-person-rule-concept/)  
- [ScaleSec - Understanding AWS Service Control Policies](https://scalesec.com/blog/understanding-aws-service-control-policies/)  

Example Policies:

- [AWS - SCPs included within AWS documentation](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps_examples.html)  
- [AWS - GitHub repository containing example SCPs](https://github.com/aws-samples/service-control-policy-examples)
- Vendor / Open Source Projects for SCPs:  
      - [ScaleSec](https://github.com/ScaleSec/terraform_aws_scp)
      - [PrimeHarbor](https://github.com/primeharbor/aws-service-control-policies/tree/main)  
      - [ASecureCloud](https://asecure.cloud/l/scp/)  
      - [CloudPosse](https://github.com/cloudposse/terraform-aws-service-control-policies/tree/main/catalog)  
      - [Salesforce’s Allowlister](https://github.com/salesforce/aws-allowlister) - Creates SCPs that only allow AWS services compliant with preferred compliance frameworks (e.g., PCI, HIPAA, HITRUST, FedRamp High, FedRamp Moderate).  

## Resource Control Policies (RCPs)

The introduction of [Resource Control Policies (RCPs)](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_rcps.html) by AWS addresses critical security challenges inherent in cloud environments. While SCPs effectively set permission boundaries for IAM principals within an organization, they do not govern resource-based policies. This limitation can lead to unintended / backdoor access if resource policies are misconfigured, as SCPs cannot restrict permissions granted through resource-based policies. Additionally, managing these resource policies individually across a sprawling infrastructure is complex and burdensome for security teams. RCPs mitigate this issue by enabling centralized enforcement of access controls directly on resources across all member accounts within an AWS Organization.

RCPs are a type of authorization policy that provides you with centralized control over the maximum permissions that are available for the resources within your AWS Organization. By design, RCPs restrict permissions rather than grant them. Thus, they create permission guardrails and ensure that resources within AWS Organizations can only be accessed within these predefined access boundaries. Unlike SCPs, which are principal-centric, RCPs are resource-centric, focusing on controlling access to AWS resources. Below are key considerations when implementing RCPs:

### RCP Applicability Scope
 
- RCPs apply only to resources managed by member accounts within your organization. They do not apply to resources that reside outside your organization.  
      - **Example**: If an IAM principal in your member account (Account A) is trying to access an Amazon S3 bucket in Account B, then the RCP attached to Account A does not apply to the S3 bucket in Account B.  

- Unlike SCPs, which only apply to IAM principals within your organization, RCPs apply to principals external to your organization when they try to access resources within your organization.  
      - **Example**: If an IAM principal in an external account (Account B) is trying to access an Amazon S3 bucket in your member account (Account A), then the RCP attached to account A applies to the principal when trying to access the S3 bucket.  

- RCPs apply to the following AWS services:  
      - Amazon S3  
      - AWS Key Management Service (KMS)  
          - However, RCPs do not apply to AWS-managed KMS keys as those are managed and used by AWS services on your behalf.  
      - AWS Secrets Manager  
      - Amazon SQS  
      - AWS Security Token Service (STS)  

- RCPs do not apply to resources within the management account. However, they do apply to resources within delegated admin accounts.  

- RCPs cannot be used to restrict access to service-linked roles.

### RCP Permission Evaluation Logic

- By default, when RCPs are enabled, AWS applies a managed RCP, `RCPFullAWSAccess` to all entities (root, OUs, accounts) in the organization, which allow access to pass through RCPs and assure that all your existing IAM permissions continue to operate as they did until more restrictive policies are applied. This policy cannot be detached.
- The permissions for a resource are restricted by the RCPs applied at every level above it in the organization. If a specific permission is denied or not explicitly allowed at any parent level (root, OUs, or resource’s account), the action cannot be performed on the resource, even if the resource owner attaches a resource policy that allows full access to the principal.  
- When a principal makes a request to access a resource within an account governed by an RCP, the RCP becomes part of the policy evaluation logic to determine whether the action is permitted. This applies regardless of whether the requesting principal belongs to the same organization or an external account.  
- Since RCPs do not grant permissions, IAM principals must still be explicitly granted access via IAM policies. If an IAM principal lacks appropriate IAM permissions, they cannot perform the actions, even if an RCP allows those actions on the resource.  
- If permissions boundaries are present, access must be allowed by all three mechanisms — RCPs, permission boundaries, and IAM policies - to perform the action.

The flowchart below provides a high-level overview of how access decisions are made when RCPs are enabled:  
![Permissions Evaluation Logic - RCPs](images/Permissions%20Evaluation%20Logic%20-%20RCPs.png)


### RCP Development and Testing
 
- Use “Deny” statements to enforce baseline security controls that you want to apply across your entire organization.  
      - **Example**: Block resource access for principals external to the organization.
```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "EnforceOrgIdentities",
            "Effect": "Deny",
            "Principal": "*",
            "Action": [
                "s3:*",
                "sqs:*",
                "kms:*",
                "secretsmanager:*",
                "sts:AssumeRole",
                "sts:DecodeAuthorizationMessage",
                "sts:GetAccessKeyInfo",
                "sts:GetFederationToken",
                "sts:GetServiceBearerToken",
                "sts:GetSessionToken",
                "sts:SetContext"
            ],
            "Resource": "*",
            "Condition": {
                "StringNotEqualsIfExists": {
                    "aws:PrincipalOrgID": "<org-id>"
                }
            }
        }
    ]
}
```
 
- Use “Deny” statements with conditions to manage exceptions or enforce certain specific controls.  
      - **Example**: Only allow service actions that are made using secure transport protocol (HTTPS). 
```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "EnforceSecureTransport",
            "Effect": "Deny",
            "Principal": "*",
            "Action": [
                "sts:*",
                "s3:*",
                "sqs:*",
                "secretsmanager:*",
                "kms:*"
            ],
            "Resource": "*",
            "Condition": {
                "BoolIfExists": {
                    "aws:SecureTransport": "false"
                }
            }
        }
    ]
}
```  
 
- AWS currently does not have any features or mechanisms to run RCPs in audit-mode to monitor the behavior and ascertain that RCPs won’t inadvertently cause disruptions.  
      - RCPs should be deployed to non-production accounts / OUs first to confirm they meet the requirements and are not causing disruptions. Only once there’s reasonable assurance around the behavior of RCPs can the scope be extended to production accounts / OUs be extended.
      - Enable CloudTrail logging and query for access denied events. Analyze the log entries to determine that all the denied events are intended and by design, and RCPs are not blocking legitimate actions.
      - Never apply RCPs directly to the root OUs before testing in lower / non-production accounts / OUs.
- Like SCPs, RCPs have the same quotas and limits - policy size of 5120 characters, and 5 RCPs per entity (root, OUs, accounts). 

### RCP Reference Materials

Documentation, Blog Posts, and Videos:

- [Introducing resource control policies (RCPs), a new type of authorization policy in AWS Organizations](https://aws.amazon.com/blogs/aws/introducing-resource-control-policies-rcps-a-new-authorization-policy/)  
- [AWS re:Invent 2024 - New governance capabilities for multi-account environments](https://www.youtube.com/watch?v=Zw8iRP0v0zA&list=PLdq8VB0hSfcYjWMBLrItQTNSbhXZ-jElD&index=63)

- [Wiz - How to use AWS Resource Control Policies](https://www.wiz.io/blog/how-to-use-aws-resource-control-policies)


Example Policies:

- [AWS - RCPs included within AWS documentation](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_rcps_examples.html)  
- [AWS - GitHub repository containing example RCPs](https://github.com/aws-samples/data-perimeter-policy-examples/tree/main/resource_control_policies)


## Access Evaluation Logic

The overall access evaluation logic that AWS applies to determine whether an action is allowed or not is much more complex than what is described above for RCPs and SCPs. The above visuals only walk through how these Authorization Policies function conceptually to help enforce access controls and security requirements. There are other types of policies as well in the flow (e.g., resource policies, session policies, IAM policies, etc.), that increase the complexity of how access is evaluated. The below [flowchart from AWS](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic_policy-eval-denyallow.html) is a comprehensive walkthrough of how access decisions are made:
<be>
<be>
<be>
![Complete Access Evaluation Logic](images/Complete%20Access%20Evaluation%20Logic.png)

## Data Perimeter

When SCPs and RCPs are used together, they establish the foundational components for a [data perimeter](https://aws.amazon.com/identity/data-perimeters-on-aws/) within your organization. At a high level, a data perimeter involves three key components— trusted identities, trusted resources, and expected networks — that work together to ensure that only whitelisted identities from known networks can access your organization’s resources.

- **Trusted Identities**: IAM principals within the organization, explicitly trusted external accounts, or AWS on your behalf.  
- **Trusted Resources**: Resources within your organization, resources belonging to explicitly trusted external accounts, or resources that AWS uses on your behalf.  
- **Expected Networks**: Your VPCs, on-premise networks, or networks that AWS uses on your behalf.

The diagram below from AWS provides a high-level overview of the concept of data perimeters:

![Data Perimeter Overview](images/Data%20Perimeter%20Overview.png)

By implementing _only_ SCPs and RCPs, you will have an accelerated start on the journey of setting up a data perimeter. However, this alone will not give you a full setup that covers all services. For a robust implementation of a data perimeter, there are other key elements (and arguably the harder ones to implement), listed below, that also need to be in place:

- [**Resource Policies**](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_identity-vs-resource.html): Not all AWS services that support resource policies are also supported by RCPs (e.g., SNS, ECR, API Gateways). For these services, resource policies will still need to be applied in a decentralized manner on a per-resource basis, significantly increasing the complexity of extending the perimeter to these additional services.  
- [**VPC Endpoint Policies**](https://docs.aws.amazon.com/vpc/latest/privatelink/vpc-endpoints-access.html#vpc-endpoint-policies-interface): To enforce that identities and resources are accessed from **expected networks**, AWS recommends using VPC endpoint policies. However, like resource policies, configuring and managing VPC endpoints at scale across all the VPCs in your organization for every supported AWS service is complex and requires significant effort.  
      - AWS’s whitepaper on secure and scalable networking architecture includes a section on implementing centralized VPC endpoints in a hub-and-spoke model. The whitepaper can be found [here](https://docs.aws.amazon.com/whitepapers/latest/building-scalable-secure-multi-vpc-network-infrastructure/centralized-access-to-vpc-private-endpoints.html).

The flowchart below outlines how the different policies, along with the requisite IAM condition keys, work together to achieve a secure data perimeter:

![Data Perimeter - How To](images/Data%20Perimeter%20-%20How%20To.png)

In conclusion, SCPs and RCPs are an important stride toward building a data perimeter that aligns trusted identities, trusted resources, and expected networks. However, progressing from here to a fully realized data perimeter is a strategic, multi-layered effort that must evolve in lockstep with the complexity of your AWS environments. Achieving this level of control involves deep insights into the inner workings of your AWS environment, including the identity models of each service, the metadata tags that guide resource governance, and the network paths — both on-premises and in the cloud — that support data flows. You must also know exactly which third parties interact with your systems and from which locations, and maintain visibility into how these relationships change over time.

This effort involves incrementally expanding beyond the basics, starting with core AWS services and methodically layering on additional controls for other resources. Over time, it will also require the incorporation of resource policies, VPC endpoint policies, and other service-specific measures to tighten the perimeter. Additionally, a well-defined tagging strategy is essential as it enables consistent governance, supports automated guardrails, helps with exception management, and simplifies the application of policies across large, dynamic environments. 

Ultimately, implementing a robust data perimeter is a multi-year undertaking that requires time, operational discipline, and organizational buy-in. It relies on strong foundational elements such as granular identity controls, consistent tagging practices, well-managed exceptions, resource governance, and secure network setup. By taking a phased, service-by-service approach and continually refining your controls, you can evolve from a simple perimeter concept into a fully realized data perimeter that safeguards your organization’s critical assets in a complex and ever-evolving AWS landscape.

### Data Perimeter Reference Materials

Documentation, Blog Posts, and Videos:

- [AWS - Blog Post Series: Establishing a Data Perimeter on AWS](https://aws.amazon.com/identity/data-perimeters-blog-post-series/)  
- [AWS re:Inforce 2024 - Establishing a data perimeter on AWS, featuring Capital One (IAM305)](https://www.youtube.com/watch?v=te8GsFjB6Fw)

Example Policies:

- [AWS - GitHub repository containing example data perimeter policies](https://github.com/aws-samples/data-perimeter-policy-examples)

## Closing Thoughts

Both SCPs and RCPs are integral for managing permissions and enforcing governance across multi-account AWS environments. While SCPs set permission guardrails for IAM principals, RCPs set permission guardrails for resources. In addition to defining maximum available permissions for principals and resources within your organization, SCPs and RCPs can also be used to enforce security controls (e.g., preventing users from uploading unencrypted S3 objects, enforcing IMDSv2 for EC2 instances, or requiring HTTPS connections to resources). Together, these policies provide a centralized capability to control access, enforce security requirements, and also lay the foundations for a well-defined data perimeter.

This is part 1 of mult-part blog series where in the next blog(s), I will try to do a similar deep-dive into the different types of Management Policies.
