# Deep Dive: AWS Organization Policies (Part 1\)

## Introduction

Today, companies heavily use AWS Organizations or AWS Control Tower for managing their multi-account AWS environments, in alignment with AWS best practices, to meet their business, governance, security, and operational goals. This approach enables efficient grouping of workloads by business units and functions, workload isolation, application of security controls by environment (development, testing, and production), improved management of quotas and service limits, minimized blast radius for IT failures or security breaches, and restricted access to sensitive data. However, while multi-account strategies enhance flexibility, scalability, and security, they also introduce new challenges. Managing accounts at scale \- consistently enforcing security and governance, streamlining operations \- can quickly become complex. This is where [AWS Organization Policies](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies.html) play a pivotal role, providing a centralized framework to maintain control, enforce guardrails, and ensure governance at scale.

AWS Organization Policies are a critical feature for managing and governing multiple AWS accounts in a centralized, scalable, and efficient manner. They are rules applied at the organizational level to manage permissions, enforce compliance, control resource access, and standardize configurations across AWS accounts. Acting as guardrails, these policies ensure that all accounts within an organization operate within defined boundaries, balancing flexibility with governance. Key benefits of implementing AWS Organization Policies include:

* **Centralized Management**: Simplifies governance by allowing administrators to manage multiple accounts from a single location, reducing operational overhead and complexity by applying policies consistently across all accounts.  
* **Enhanced Security**: Enforces security best practices, protects sensitive resources, and ensures a consistent security posture using least-privilege access controls across your company’s AWS environment.  
* **Operational Efficiency**: Reduces manual effort by automating governance and policy management while standardizing configurations across accounts to streamline operations.

There are 2 types of AWS Organization Policies:

* [Authorization Policies](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_authorization_policies.html): Authorization policies provide the ability to centrally define and enforce the maximum available permissions for principals and resources within your AWS Organizations. The 2 types of Authorization Policies are:
         * [Service Control Policies (SCPs)](#service-control-policies-scps): SCPs allow you to centrally define and enforce maximum available permissions for principals (IAM users, root users, and roles) within your AWS Organizations.   
         * [Resource Control Policies (RCPs)](#resource-control-policies-rcps): RCPs allow you to centrally define and enforce the maximum available permissions for resources within your AWS Organizations.

   
* [Management Policies](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_management_policies.html): Management policies provide the ability to centrally define and enforce configurations on services and resources within your AWS Organizations. The different types of Management Policies are:
         * Declarative Policies: Declarative policies allow you to centrally define and enforce baseline configuration of resources within your AWS Organizations.  
         * Backup Policies: Backup policies allow you to centrally manage backups for resources within your AWS Organizations.   
         * Tag Policies: Tag policies allow you to centrally enforce tagging standards on resources within your AWS Organizations.   
         * Chatbot Policies: Chatbot policies allow you to centrally restrict access to resources within your AWS Organizations, from Teams, Slack, etc.   
         * AI Services Opt-Out Policies: AI policies allow you to centrally control access to your data and prevent them from being used in development of AWS’ AI services

In the remainder of this blog (Part 1), I will take a deep-dive into the two types of Authorization Policies: SCPs and RCPs. I will follow this with a subsequent blog (Part 2\) that delves into the various types of Management Policies.

## Service Control Policies (SCPs)

| Does not affect Management account | Maximum size of policy document \- 5120 characters | Maximum number that can be attached to a root, OU, or account \- 5 |

[SCPs](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html) are a type of authorization policy that provides you with centralized control over the maximum permissions that are available to the principals (IAM users, root users, roles) within your AWS Organization. By design, SCPs restrict permissions rather than grant them. Thus, they create permission guardrails and ensure that principals within AWS Organizations operate within these predefined access boundaries. Below are key considerations when implementing SCPs:

### SCP Applicability Scope

* SCPs apply only to IAM principals managed by member accounts within your organization. They do not apply to IAM principals that reside outside your organization.  
* SCPs do not apply to policies attached directly to resources (i.e. resource policies).
       * For example, if an Amazon S3 bucket owned by account A has a bucket policy granting access to users in account B (outside the organization), the SCP attached to account A does not apply to those external users or the resource policies.
  
* SCPs do not apply to [service-linked roles](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create-service-linked-role.html).  
* SCPs do not apply to IAM principals within the management account. However, they do apply to IAM principals within delegated admin accounts.
  
* SCPs do not apply to the below tasks/entities:
        * Register for the Enterprise support plan as the root user.  
        * Provide trusted signer functionality for CloudFront private content.  
        * Configure reverse DNS for an Amazon Lightsail email server and Amazon EC2 instance as the root user.
        * Tasks on some AWS-related services:  
              * Alexa Top Sites.  
              * Alexa Web Information Service.  
              * Amazon Mechanical Turk.  
              * Amazon Product Marketing API.

### SCP Permission Evaluation Logic

* SCPs operate on a deny-by-default model. If an action or service is not explicitly allowed in the SCP, it is implicitly denied, regardless of IAM permissions.  
* The permissions of accounts are restricted by the SCPs applied at every level above it in the organization. If a specific permission is denied or not explicitly allowed at the parent level (root or OU or the principal’s account), the action cannot be performed by the principal even if has admin access.  

* SCPs do not grant permissions; hence, IAM principals need to be assigned permissions explicitly via IAM policies.  
        * For example, If access to a service (S3) is “Allowed” via the SCPs but the principal does not have permissions assigned to it explicitly via IAM policies, the principal cannot access S3.   

* If an IAM principal has an IAM policy that grants access to an action:  
        * and the SCP also explicitly allows the action, then the principal can perform that action  
        * but the SCP does not explicitly allow or is denied, then the principal cannot perform that action  

* If permissions boundaries are present, access must be allowed by all 3 \- SCPs, permission boundaries, and IAM policies \- to perform the action.

The below flowchart provides a high-level overview on how access decisions are made when SCPs are enabled:  
![Permissions Evaluation Logic - SCPs](images/Permissions%20Evaluation%20Logic%20-%20SCPs.png)

### SCP Development and Testing

* Use “Deny” statements to enforce baseline security controls that you want to apply across your entire organization.  
      * For example, you want to prevent the member accounts from leaving your organization.
```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Deny",
            "Action": [
                "organizations:LeaveOrganization"
            ],
            "Resource": "*"
        }
    ]
}
```

* Use “Deny” statements with conditions to manage exceptions or enforce certain specific controls. 
      * For example, you want to block all S3 actions if the requests are not made using secure transport protocol (HTTPS).
```
  {
      "Version": "2012-10-17",
      "Statement": [
          {
              "Effect": "Deny",
              "Action": "s3:*",
              "Resource": "*",
              "Condition": {
                  "Bool": {
                      "aws:SecureTransport": "false"
                  }
              }
          }
      ]
  }
```

      * For example, you want to prevent high-risk roles from changes except when made by whitelisted admin roles. 
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
                      "aws:PrincipalARN":"arn:aws:iam::*:role/<approved admin that can make changes>"
                  }
              }
          }
      ]
  }
```

* By default, AWS applies the managed SCP, [FullAWSAccess](https://console.aws.amazon.com/organizations/?#/policies/p-FullAWSAccess), to all entities in the organization, which grants access to all services and actions. Be careful in removing this policy and not replacing it with another suitable policy (one that explicitly allows access to your desired list of services), at any level within the organization, as you can inadvertently end up locking yourself out.
          * For example, you want to only provide accessed to approved services (S3, EC2, DynamoDB) and block all other services. You can do this by applying the below SCP and removing the default AWS managed SCP - FullAWSAccess.
```
     {
     "Version": "2012-10-17",
         "Statement": [
             {
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

* AWS currently does not have any features or mechanisms to run SCPs in audit-mode to monitor the behavior and ascertain that SCPs won’t inadvertently cause disruptions.  
       * Leverage [service last accessed data in IAM](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_access-advisor.html) to determine which services are in use v/s not and then use this insight to develop SCPs.   
       * SCPs should be deployed to non-production accounts / OUs first to confirm they meet the requirements and are not causing disruptions. Once there’s reasonable assurance around the behavior of SCPs, only then extend the scope to production accounts / OUs.   
       * Enable CloudTrail logging and query for access denied events where the failure reason is “service control policy”. Analyze the log entries to determine that all the denied events are intended and by design, and they are not blocking legitimate actions.  
       * Never apply SCPs directly to the root OUs before testing in lower / non-production accounts / OUs. 

### SCP Reference Materials

#### Documentation, Blog Posts, and Videos:

* [Codify your best practices using service control policies: Part 1](https://aws.amazon.com/blogs/mt/codify-your-best-practices-using-service-control-policies-part-1/)  
* [Codify your best practices using service control policies: Part 2](https://aws.amazon.com/blogs/mt/codify-your-best-practices-using-service-control-policies-part-2/)   
* [Best Practices for AWS Organizations Service Control Policies in a Multi-Account Environment](https://aws.amazon.com/blogs/industries/best-practices-for-aws-organizations-service-control-policies-in-a-multi-account-environment/)
* [SummitRoute - AWS SCP Best Practices](https://summitroute.com/blog/2020/03/25/aws_scp_best_practices/#two-person-rule-concept/)  
* [ScaleSec \-  Understanding AWS Service Control Policies](https://scalesec.com/blog/understanding-aws-service-control-policies/)   
* [How to use AWS Organizations to simplify security at enormous scale](https://aws.amazon.com/blogs/security/how-to-use-aws-organizations-to-simplify-security-at-enormous-scale/)  
* [Identity Guide – Preventive controls with AWS Identity – SCPs](https://aws.amazon.com/blogs/mt/identity-guide-preventive-controls-with-aws-identity-scps/)  
* [Best Practices for AWS Organizations Service Control Policies in a Multi-Account Environment](https://aws.amazon.com/blogs/industries/best-practices-for-aws-organizations-service-control-policies-in-a-multi-account-environment/)  
* [Control VPC sharing in an AWS multi-account setup with service control policies](https://aws.amazon.com/blogs/security/control-vpc-sharing-in-an-aws-multi-account-setup-with-service-control-policies/)  
* [Get more out of service control policies in a multi-account environment](https://aws.amazon.com/blogs/security/get-more-out-of-service-control-policies-in-a-multi-account-environment/)
       
#### Example Policies

* [AWS documentation containing SCPs](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps_examples.html)  
* [AWS Samples \- Service Control Policy Examples](https://github.com/aws-samples/service-control-policy-examples)  
* Vendor / Open Source Projects for SCPs:  
    * [ScaleSec \- Example SCPs](https://github.com/ScaleSec/terraform_aws_scp)  
    * [PrimeHarbor \- Example SCPs](https://github.com/primeharbor/aws-service-control-policies/tree/main)  
    * [ASecureCloud \- Example SCPs](https://asecure.cloud/l/scp/)  
    * [CloudPosse \- Example SCPs](https://github.com/cloudposse/terraform-aws-service-control-policies/tree/main/catalog)  
    * [Salesforce’s Allowlister](https://github.com/salesforce/aws-allowlister) \- Creates SCP that only allow AWS services that are compliant with preferred compliance frameworks (e.g., PCI, HIPAA, HITRUST, FedRamp High, FedRamp Moderate)

## Resource Control Policies (RCPs)

| Does not affect Management account | Maximum size of policy document \- 5120 characters | Maximum number that can be attached to a root, OU, or account \- 5 |

The introduction of Resource Control Policies (RCPs) by AWS addresses critical security challenges inherent in cloud environments. While Service Control Policies (SCPs) effectively set permission boundaries for IAM principals within an organization, they do not govern resource-based policies. This limitation can lead to unintended access if resource policies are misconfigured, as SCPs cannot restrict permissions granted through resource-based policies. Managing these resource policies individually across a sprawling infrastructure is complex and burdensome for security teams. RCPs mitigate this issue by enabling centralized enforcement of access controls directly on resources across all member accounts within an AWS Organization. 

[RCPs](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_rcps.html) are a type of authorization policy that provides you with centralized control over the maximum permissions that are available for the resources within your AWS Organization. By design, RCPs restrict permissions rather than grant them. Thus, they create permission guardrails and ensure that resources within AWS Organizations can only be accessed within these predefined access boundaries. Unlike SCPs, which are principal-centric, RCPs are resource-centric, focusing on controlling access to AWS resources. Below are key considerations when implementing RCPs:

### RCP Applicability Scope

* RCPs apply only to resources managed by member accounts within your organization. They do not apply to resources that reside outside your organization.  
  * For example, if an IAM principal in your member account (Account A) is trying to access an Amazon S3 bucket in account B, then the RCP attached to account A does not apply to the S3 bucket in Account B.  
* Unlike SCPs which only apply to IAM principals within your organization, RCPs apply to principals, external to your organization, when they try to access resources within your organization.  
  * For example, if an IAM principal in an external account (Account B) is trying to access an Amazon S3 bucket in your member account (Account A), then the RCP attached to account A applies to the S3 bucket.    
* RCPs apply to the following AWS services:  
  * Amazon S3  
  * AWS Key Management Service (KMS)  
    * However, RCPs do not apply to AWS managed KMS keys as those are managed and used by AWS services on your behalf.   
  * AWS Secrets Manager  
  * Amazon SQS  
  * AWS Security Token Service (STS)  
* RCPs do not apply to resources within the management account. However, they do apply to resources within delegated admin accounts.  
* RCPs cannot be used to restrict access to service-linked roles.

### RCP Permission Evaluation Logic

* The permissions for a resource are restricted by the RCPs applied at every level above it in the organization. If a specific permission is denied or not explicitly allowed at any parent level (root or OUs or resource’s account), the action cannot be performed on the resource, even if the resource owner attaches a resource-based policy that allows full access to the principal.  
* When a principal makes a request to access a resource within an account governed by an RCP, the RCP becomes part of the policy evaluation logic to determine whether the action is permitted. This applies regardless of whether the requesting principal belongs to the same organization or an external account.  
* Since RCPs do not grant permissions, IAM principals must still be explicitly granted access via IAM policies. If an IAM principal lacks appropriate IAM permissions, they cannot perform the actions, even if an RCP allows those actions on the resource.  
* If permissions boundaries are present, access must be allowed by all 3 \- RCPs, permission boundaries, and IAM policies \- to perform the action.

The below flowchart provides a high-level overview on how access decisions are made when RCPs are enabled:  
![Permissions Evaluation Logic - RCPs](images/Permissions%20Evaluation%20Logic%20-%20RCPs.png)

### RCP Development and Testing

* Use “Deny” statements to enforce baseline security controls that you want to apply across your entire organization.  
  * For example, you want to block resource access for principals external to your organization.   
* Use “Deny” statements with conditions to manage exceptions or enforce certain specific controls.  
  * For example, you want to allow S3 access to only principals in your organization and your known third party accounts.   
* By default, AWS applies a managed RCP, RCPFullAWSAccess to all entities in the organization, which allow access to pass through RCPs and assure that all your existing IAM permissions continue to operate as they did. This policy cannot be detached.  
* AWS currently does not have any features or mechanisms to run RCPs in audit-mode to monitor the behavior and ascertain that RCPs won’t inadvertently cause disruptions.  
  * RCPs should be deployed to non-production accounts / OUs first to confirm they meet the requirements and are not causing disruptions. Once there’s reasonable assurance around the behavior of SCPs, only then extend the scope to production accounts / OUs.   
  * Enable CloudTrail logging and query for access denied events. Analyze the log entries to determine that all the denied events are intended and by design, and they are not blocking legitimate actions.  
  * Never apply RCPs directly to the root OUs before testing in lower / non-production accounts / OUs.

### RCP Reference Materials

#### Documentation, Blog Posts, and Videos

  * [Introducing resource control policies (RCPs), a new type of authorization policy in AWS Organizations](https://aws.amazon.com/blogs/aws/introducing-resource-control-policies-rcps-a-new-authorization-policy/)  
  * [Wiz \- How to use AWS Resource Control Policies](https://www.wiz.io/blog/how-to-use-aws-resource-control-policies)

#### Example Policies

  * [AWS documentation containing RCP policies](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_rcps_examples.html)  
  * [AWS Samples \- RCP Policy Examples](https://github.com/aws-samples/data-perimeter-policy-examples/tree/main/resource_control_policies)  
    

## Access Evaluation Logic

The overall access evaluation logic that AWS applies to determine whether action is allowed or not is much more complex than what is described above for RCPs and SCPs. The above visuals were only to conceptually walkthrough how these Authorization Policies function conceptually to help enforce access controls and security requirements. There are other types of policies as well in the flow (e.g., resource policies, session policies, IAM policies, etc.), that increase the complexity in how access is evaluated. The below [flowchart from AWS](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic_policy-eval-denyallow.html) is a comprehensive walkthrough of how access decisions are made: 

![Complete Access Evaluation Logic](images/Complete%20Access%20Evaluation%20Logic.png)

## Data Perimeter

When SCPs and RCPs are used together, they establish the foundational components for a [data perimeter](https://aws.amazon.com/identity/data-perimeters-on-aws/) within your organization. At a high-level, data perimeter involves 3 key components \- trusted identities, trusted resources, expected networks \- that work together to ensure that only whitelisted identities, from known networks can access your organization’s resources.

* **Trusted Identities**: IAM principals within the organization, explicitly trusted external accounts, or AWS on your behalf.  
* **Trusted Resources**: Resources within your organization, resources belonging to explicitly trusted external accounts, or resources that AWS uses on your behalf.  
* **Expected Networks**: Your VPCs, on-premise networks, or networks that AWS uses on your behalf.

The below diagram from AWS provides a high-level overview of the concept of data perimeters:

![Data Perimeter Overview](images/Data%20Perimeter%20Overview.png)

By ONLY implementing SCPs and RCPs, you will have an accelerated start on the journey of setting up a data perimeter, however, it's not going to give you the full setup that covers all the services. For a robust implementation of data perimeter, there are other key elements (and arguably the harder ones to implement), listed below, that will need to be in place as well:

* [**Resource Policies**](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_identity-vs-resource.html)**:** Not all AWS services that support resource policies are also supported by RCPs (e.g., SNS, ECR, API Gateways). As such, for these services, resource policies will still need to be applied in a decentralized manner on a per resource / per account basis, thereby significantly increasing the complexity of extending the perimeter to these additional services.   
* [**VPC Endpoint Policies**](https://docs.aws.amazon.com/vpc/latest/privatelink/vpc-endpoints-access.html#vpc-endpoint-policies-interface)**:** To enforce that identities and resources are accessed from **expected networks**, AWS recommends using VPC endpoint policies to achieve the same. However, similar to resource policies, configuring and managing VPC endpoints at scale in a decentralized manner, across all the VPCs in your organization, for every supported AWS service, is complex and requires significant effort.   
  * AWS’ whitepaper on secure and scalable networking architecture has a section that talks about a pattern for implementing centralized VPC endpoints in a hub and spoke model. The whitepaper can be found [here](https://docs.aws.amazon.com/whitepapers/latest/building-scalable-secure-multi-vpc-network-infrastructure/centralized-access-to-vpc-private-endpoints.html).

The below flowchart outlines how the different policies, along with the requisite IAM condition keys, work together to achieve a secure data perimeter:

![Data Perimeter - How To](images/Data%20Perimeter%20-%20How%20To.png)

### Data Perimeter Reference Materials

### Documentation, Blog Posts, and Videos

  * [Blog Post Series: Establishing a Data Perimeter on AWS](https://aws.amazon.com/identity/data-perimeters-blog-post-series/)  
  * [AWS re:Inforce 2024 \- Establishing a data perimeter on AWS, featuring Capital One (IAM305)](https://www.youtube.com/watch?v=te8GsFjB6Fw)

### Example Policies
  * [AWS Samples \- Data Perimeter Policy Examples](https://github.com/aws-samples/data-perimeter-policy-examples)


Both SCPs and RCPs are integral for managing permissions and enforcing governance across multi-account AWS environments. While SCPs set permission guardrails for IAM principals, RCPs set permission guardrails for resources. In addition to defining maximum available permissions for principals and resources within your organization, SCPs and RCPs can also be used to enforce security controls (e.g., preventing users from uploading unencrypted S3 objects, enforcing IMDSv2 for EC2 instances, or requiring HTTPS connections to resources). Together, these policies provide a centralized capability to enforce access controls and security requirements consistently across your entire organization at scale.
