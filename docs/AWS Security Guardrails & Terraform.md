# AWS Security Guardrails & Terraform

## Introduction

Traditional security approaches designed for on-premises environments are inadequate in addressing the unique risks posed by the cloud. The distributed and dynamic nature of cloud resources, speed of development and innovation, multi-tenant architectures, and decentralized operating models have resulted in a complex threat landscape that requires a fundamental shift in building and operating scalable security programs. This paradigm shift has popularized the concepts of paved roads and security guardrails to reduce the security burdens on the engineers and enable them to focus on innovation and driving business value, without compromising on security. Below, I have included some helpful resources better to explain the concepts of paved roads and security guardrails but at a high-level:

* *Paved Roads*: Originally conceptualized by Netflix, refers to a set of standardized frameworks (e.g., authentication patterns, certificate management, service mesh, etc.), self-service tools, and automated processes that are easily readily consumable by engineers, allowing them to focus on their core responsibilities and not worry about implementing security requirements.  
* *Security Guardrails*: These are preventive controls, integrated into the development workflows, that define the security boundaries and force the engineers to operate with them, thereby stopping misconfigured and vulnerable resources (code) from being released into cloud environments.

Most organizations today have adopted some form of *paved roads* or *security guardrails*, although the maturity of these implementations varies significantly. Broadly, the focus has been on two key areas: **(a) scanning and detection early in the Software Development Life Cycle (SDLC)** and **(b) ad hoc prevention of high-risk actions through CI/CD pipeline integrations and organizational policies** (e.g., Service Control Policies (SCPs), Organization Policies, or Azure Policies). These efforts prioritize proactive identification of security issues early in the development process to help catch and address them before they manifest within cloud environments.

Additionally, for many organizations operating in the cloud, implementing Cloud-Native Application Protection Platform (CNAPP) has become essential for achieving greater visibility into cloud environments and identifying diverse classes of security issues (Shameless plug \- I recently wrote blog posts on [Day 1](https://naman16.github.io/cloud-security/) and [Day 2](https://naman16.github.io/cloud-security/Implementing%20CNAPP:%20Day%202%20Focus%20Areas/) focus areas for CNAPP).

While conducting scans and generating insights is a foundational first step toward understanding and securing the environment, a critical gap remains. Organizations often lack prescriptive guidance and accessible, reusable security artifacts that engineers can leverage directly. By not providing these resources, security teams inadvertently place the burden of configuring services securely on engineers, who may lack the security expertise or resources needed to efficiently address intricate security requirements. Without “built-in” security, engineers end up spending time on tasks that could otherwise be streamlined through reusable secure Infrastructure as Code (IaC) templates (_It is best practice to leverage IaC for cloud infrastructure provisioning and management_). This kind of “secure-by-design” IaC allows engineers to meet security requirements faster, enabling them to stay focused on their primary responsibilities while maintaining a secure development pipeline.

Establishing such reusable, secure IaC offers additional benefits beyond efficiency. By actively supporting engineers with secure IaC, security teams move from a passive, reactive role into a proactive partnership, where they provide engineers with actionable solutions rather than just requirements. This approach fosters stronger relationships with development teams, as security becomes an enabler rather than a gatekeeper, actively facilitating good security practices instead of merely imposing them.

The CNAPP tools (outside of IaC scanning / policy-as-code (PaC)) are great at scanning and flagging issues and offering remediation guidance that is generally applicable for CLI or console users. However, this guidance may fall short for organizations heavily invested in IaC, as engineers must still research and implement the specific IaC parameters needed to address the issues. This gap highlights the need for security teams to go beyond issue reporting. By building and distributing *“build once, use multiple times”* secure IaC templates, organizations can streamline remediation efforts, ultimately leading to faster, more scalable, and more consistent security practices.

In summary, organizations invest significant resources in scanning and monitoring to ensure they have visibility into their security posture. Yet, a lack of centralized, reusable security artifacts often leaves engineers to interpret and implement security requirements on their own. By investing in reusable secure IaC, security teams can enable engineers to “inherit” security best practices, rather than requiring them to navigate complex configurations alone. This approach not only enhances efficiency but also builds a more collaborative relationship between security and engineering, reinforcing security as a shared responsibility across the organization.

## Solution Overview

Given the benefits of secure IaC templates with built-in security requirements, below is a high-level overview of automation that leverages Artificial Intelligence (AI) to develop:

* List of security requirements for several commonly used AWS services  
* Secure Terraform modules that codify these security requirements

### Requirements Generator

The Requirements Generator (requirements-generator.py) is a Python script that consolidates and enhances AWS service security requirements from multiple scanning tools ([Checkov](https://www.checkov.io/5.Policy%20Index/terraform.html) and [Prowler](https://github.com/prowler-cloud/prowler)). The script leverages Anthropic’s Claude 3.5 Sonnet model through AWS Bedrock and through prompt engineering, aims to transform the security requirements from these distinct sources into comprehensive, well-structured guidelines that engineers can easily understand and implement. Below are the key features that I have tried to implement:

* **Multi-Source Integration**: Combines security requirements from multiple sources (Prowler and Checkov) into a unified format  
* **Intelligent Deduplication**: Merges duplicate requirements while maintaining distinct requirements for different resources  
* **Environment-Aware Processing**: Considers specific AWS environment configurations like hub-and-spoke network architecture and SSO setup  
* **Standardized Output**: Generates consistently formatted JSON output with required fields like ID, name, description, cloud provider, and security domain  
* **Comprehensive Coverage**: Identifies gaps in security requirements and adds missing controls based on AWS best practices

Below is the large language model (LLM) prompt that I am currently using for requirements generation:

```
You are a cloud security expert that is tasked with defining detailed technical security requirements AWS services. 
The security requirements should be clear, well-worded, and descriptive with all the necessary details such that it can be easily understood and implemented by developers.
  
  Follow the below guidelines when developing technical security requirements:
  1. Below are the key details about my AWS environment's setup that needs to be adhered to always:
      - Network is setup to follow a hub and spoke architecture where the VPCs are connected to each other via Transit Gateways.
      - AWS management console access is federated through SSO via AWS Identity Center. IAM users are only created as an exception.  
      - AWS IAM user access keys are banned from use and instead IAM roles should be used.
      - CloudTrail management events have been enabled for all my AWS accounts for all services.
      - VPC flow logs have been enabled for all my VPCs for all AWS accounts. 
      - You can assume that all the resources are only private and have no requirement for any sort of public access.
      - Any resources that need to be publicly exposed to the internet, are managed separately and is outside the scope of the requirements defined here. 

  2. You will be provided security requirements enclosed within the <security requirements> tag for different AWS services as a starting point. 
      - If there are duplicative requirements on the same resource, combine them.
      - If the security violates / do not follow my environment's specific setup, remove them. 
      - if there are 2 requirements on the same resource for the same configuration, combine them into 1.
          - For example: If there are 2 requirements for encryption-at-rest on sagemaker notebook, combine them into 1.
      - If there are 2 requirements on 2 different resources for the same configuration, keep them separate. 
          - For example: If there is 1 requirement for encryption-at-rest on sagemaker notebook and another 1 for encryption-at-rest on sagemaker domain, keep them as separate.

  3. Add any missing security requirements for the given service and all of its resources to ensure a robust and comprehensive library of security requirements.          
     - Examples of security requirements that should be added if missing: use latest TLS policies, enforce HTTPS, disable public access, enable encryption at-rest using CMK, etc.

  4. When writing the "name" and "description", make it very clear and well-worded such that it is easy to understand and can be easily implemented by developers.
     - The "name" of the requirement should be a proper sentence and should be easy to understand. 
     - The "description" of the requirement should be detailed and should contain implementation details for that requirement. 
     - Pack all the details and context in the "name" and "description" of the requirement to make it easy to understand and implement for developers.
     - Don't abstract any details by using generic phrases like "apply secure settings". Instead, enumerate each setting that needs to be applied - "enabling TLS, enabling audit logging, enabling user activity logging, etc."  
     - Don't develop security requirements that are vague or generic.
     - The granularity / specificity of these security requirements should be such that it can be interpreted by developers and translated into IaC easily.

  5. When defining security requirements for the AWS service, only focus on requirements for that service. Don't define requirements for other services.
     - For example:
          - Avoid requirements like "Implement Regular Key Rotation for AppFlow KMS Keys" because this is captured in the requirements for AWS KMS by an overarching requirement like "Customer managed keys (CMK) should have rotation enabled for every 90 days".
          - Within AppFlow, we should only call out a requirement like "Use AWS KMS Customer Managed Key (CMK) for AppFlow Flow Encryption".

  6. Perform a detailed review on the developed security requirements to make sure the guidelines are followed and the below hold true:            
      - Requirements like "Enable AWS CloudTrail Logging for MSK Cluster API Calls" "Enable AWS CloudTrail Logging for AppFlow API Calls" don't exist because CloudTrail logs are already enabled for all services.
      - Requirements like ""Enable VPC Flow Logs for MWAA VPC" don't exist because VPC flow logs have been enabled for my VPCs. 
      - Requirements like "Implement Multi-Factor Authentication for Critical Route53 Changes" don't exist because federation / SSO through Identity Center enforces MFA.
      - Requirements with generic phrases like "restrict access" or "enforce principal of least privilege" don't exist. Instead, they are written more clearly like "restrict access to only known principals or accounts".
      - Vague requirements that are subject to interpretation don't exist.
          - For example: Requirements like "Ensure Proper Configuration of Elastic Load Balancer Listeners" and "Implement Secure Listener Rules for Application Load Balancers" don't exist. These are bad requirements because it is not clear how to implement this and is subject to interpretation by the developers. Instead, these requirements should be written where the exact configurations (HTTPS and latest TLS policies) are specified very clearly to ensure that all the necessary details are provided to implement secure load balancer listeners.       
      - Requirements are defined on all the different resources for the AWS service. 
          - For example: If there are requirements only for sagemaker domain but not sagemaker notebook, develop requirements for sagemaker notebook. Keep the requirements for sagemaker domain and sagemaker notebook separate, don't combine them.
      - Requirements where different types of configurations are combined don't exist. Instead, keep them as 2 separate requirements.
          - For example: "Enable encryption at rest and in transit for MSK Cluster" is a bad requirement. These should be split into 2 separate requirements like "Use KMS CMK for encryption-at-rest for MSK Cluster" and "Use latest TLS policies for encryption-in-transit for MSK Cluster".
      - Requirements where different types of resources are combined don't exist. Instead, keep them as 2 separate requirements. 
          - For example:
              - "Use KMS CMK for encryption-at-rest for SageMaker Domain and Notebook Instance" is a bad requirement. These should be split into 2 separate requirements like "Use KMS CMK for encryption-at-rest for SageMaker Domain" and "Use KMS CMK for encryption-at-rest for SageMaker Notebook Instance"
              - "Use Non-Default Ports for RDS Instances and Clusters" is a bad requirement. These should be split into 2 separate requirements like "Use Non-Default Ports for RDS Instances" and "Use Non-Default Ports for RDS Clusters"
  
  7. Update requirement IDs to follow format 'service:001', 'service:002', etc.
      - For example: s3:001; s3:002; s3:003, etc.
  
  8. Assign a "domain" to each requirement based on "name" and "description".
     - Possible values:
          - data protection
          - network security
          - identity and access management
          - logging and monitoring
          - secure configuration
 
  9. Ensure each requirement has these fields in this exact order:
     - ID (format: service:00X)
     - name (brief title)
     - description (detailed explanation)
     - cloudProvider (always "AWS")
     - domain

Respond with ONLY a valid JSON array of requirements. Do not include any explanatory text or markdown formatting.
```

### Terraform Creator

The Terraform Creator (terraform-creator.py) is a Python script that automatically generates secure Terraform modules based on the security requirements that were developed by the “Requirements Generator” script. The script utilizes Anthropic's Claude 3.5 Sonnet model through AWS Bedrock and employs prompt engineering to transform security requirements into reusable and secure Terraform modules. Below are the key features that I have attempted to implement:

* **Standardized Module Structure**: Generates three files for each AWS service:  
  * main.tf: Contains resource configurations with requirement traceability  
  * variables.tf: Defines all configurable parameters with secure default  
  * notes.md: Provides detailed implementation documentation and coverage analysis  
* **Intelligent Implementation Decisions**: Makes informed choices about requirement implementation:  
  * Assumes reusability where users will bring pre-created resource components (KMS keys, log buckets, etc.) as opposed to creating supporting resources (see below example)  
  * Avoids creating duplicate resources for implementing different requirements  
  * Creates optional read/write IAM policies for flexibility  
* **Comprehensive Documentation**: Maintains detailed documentation of implementation status:  
  * Maps security requirements to specific Terraform configurations  
  * Documents partially implemented requirements  
  * Explains requirements that cannot be implemented via Terraform  
  * Includes additional security measures beyond base requirements

Below is the LLM prompt that I am currently using for Terraform creation:

```
You are an expert in cloud security for AWS. You need to develop comprehensive, secure Terraform module for the given AWS service based on the
security requirements enclosed within the <security requirements> tag. Follow the below guidelines when developing secure Terraform modules:     
  
  1. The attempt should be to develop secure Terraform modules for all the security requirements for the given AWS service.

  2. Use the "name" and "description" fields to develop understanding of the requirement for Terraform implementation.

  3. If there are any requirements that cannot be implemented in Terraform or can only be implemented partially, do so and maintain a note in the notes.md file.
      - Don't implement requirements for VPC endpoints like "Implement VPC Endpoints for Kinesis Data Streams" because VPC endpoints are managed outside of this module.
      - Don't implement requirements like "Enable AWS CloudTrail Logging for AppFlow API Calls" because CloudTrail logging has already been enabled for all accounts and all services.
      - Since IAM policies are use-case dependent, create 1 policy for read and 1 policy for write that users can OPTIONALLY use.
      - For the same resource, don't create multiple separate resource blocks. Instead, create 1 resource block with all the configurations. 
          - For example:
              - Instead of creating 2 different resources like "resource "aws_kms_key" "main"" and "resource "aws_kms_key" "tagged"", create only 1 "aws_kms_key" with all the configurations.
              - Instead of creating 2 different resources like "resource "aws_apigatewayv2_stage" "xray"" and "resource "aws_apigatewayv2_stage" "main"", create only 1 "aws_apigatewayv2_stage" with all the configurations.

  4. DO NOT create supporting resources like s3 buckets, security groups, kms keys, cloudwatch log groups / alarms, etc. Assume that those have been created and the values will be provided.
      - For example: 
          - When enabling access logs for ALB, assume that the s3 logs destination bucket is already created and value will be provided by user as input.
          - When setting up security groups for resources (RDS, ECS, EKS, etc.), assume that the security group has already been created and value will be provided by user as input.
          - When setting up encryption on a resource, assume that the KMS key has already been created and value will be provided by user as input.              
  
  5. Even when not specified explicitly, always implement security best practices like encryption at rest for all possible resources, latest TLS policies, disabling insecure defaults (e.g. disable_execute_api_endpoint = true for aws_api_gateway_rest_api), etc.
  
  6. Below are the 3 files that should be created:
      a. main.tf: Include all necessary resources and their configurations. Add comments for each requirement that was implemented in Terraform in the format ID:name directly above the actual configuration.
      b. variables.tf: Define all variables used in main.tf, including descriptions and default values where appropriate.
          1. Set the default values to be the most secure values possible. E.g., set ALB to internal = true instead of default value of internal = false.
      c. notes.md: Provide a detailed breakdown in markdown syntax such that all requirements for the given AWS service are individually accounted for:
          1. Requirements that were implemented in the Terraform code. Ensure you implement requirements in Terraform that are partially possible and maintain a note on that. 
          2. Requirements that could be implemented but weren't included (if any) - this list should be as minimal as everything possible to implement through Terraform must be implemented.
          3. Requirements that are inherently implemented by the implementation of a different requirement.
          4. Requirements that cannot be directly implemented in Terraform along with an explanation.  
          5. Any best practices or additional security measures not mentioned in the requirements but relevant to the AWS service.
          6. Each of the requirements for the given AWS should be its own individual line, don't merge requirements like S3-001, S3-002, etc. in 1 row.
          7. Example format for notes.md is provided below within the <notes.md example> tag.
  
  7. Review all the 3 files generated to make sure that they are accurate, align to the provided security requirements for the AWS service, and follow all the rules specified above.

Ensure that the Terraform code is well-commented, follows best practices, and is as secure as possible. Include input variables for all configurable parameters to make the module reusable.

Format your response exactly as below within the XML tags and do not include anything else:

<main.tf>
main.tf content
</main.tf>

<variables.tf>
variables.tf content
</variables.tf>

<notes.md>
notes.md content
</notes.md>
```

\n

Below is an illustrative example to highlight how Terraform modules can be reused:

![Terraform Module Reusability - Example](images/Terraform%20Module%20Reusability%20-%20Example.png)

## Closing Thoughts

While this implementation primarily focused on developing security requirements and Terraform modules for AWS, it provides a flexible framework that can be customized for other IaC languages, cloud providers, and security requirements. By updating the prompts for the LLM and adjusting configurations—such as integrating Prowler and Checkov’s policies for Azure or GCP, incorporating security requirements from alternative tools, or using your own requirements—this automation can be adapted to suit various use-cases.

With the help of AI, I was able to create these requirements and modules in a few hours with reasonable accuracy, which would otherwise have taken me weeks or even months. However, since the requirements and modules are AI-generated, it’s important to use them with caution; I recommend reviewing, validating, and tailoring the content to meet your specific needs. Rather than viewing this as a silver bullet, I see it as an enabler for enhancing efficiency in developing secure IaC. Overall, I am optimistic about its potential benefits:

* **Time Savings for Engineers**: They can avoid starting from scratch when implementing security configurations.  
* **Support for Security Teams**: AI can help alleviate the burden of developing remediation guidance, allowing teams to focus on more complex issues.

While this implementation is designed to generate secure IaC starter packs, it illustrates a broader point: AI solutions can offer much-needed support to overworked security teams. As models evolve and improve, the quality of AI-generated outputs will only get better, enabling us to tackle more complex security challenges efficiently.

Resources for paved roads and security guardrails:

Resources for paved roads and security guardrails:

1. Netflix’s talk at RSA \- [Construction Time Again: A Lesson in Paving Paths for Security](https://www.rsaconference.com/library/presentation/usa/2023/Construction%20Time%20Again%20A%20Lesson%20in%20Paving%20Paths%20for%20Security?utm_source=appsec.beehiiv.com&utm_medium=referral&utm_campaign=reasonable-appsec-6-five-security-articles-guard-rails-paved-roads-photo-and-podcast-corner)  
2. Google Cloud \- [Building security guardrails for developers](https://cloud.google.com/blog/topics/inside-google-cloud/building-security-guardrails-for-developers-with-google-cloud)  
3. Resourcely’s conversation with Jason Chan \- [Guardrails and Paved Roads](https://www.resourcely.io/post/guardrails-and-paved-roads)  
4. Jason Chan’s talk at LASCON: [From Gates to Guardrails \- Alternate Approaches to Product Security](https://www.youtube.com/watch?v=geumLjxtc54)  
5. Netflix’s blog post \- [The Show Must Go On](https://netflixtechblog.com/the-show-must-go-on-securing-netflix-studios-at-scale-19b801c86479)  
6. Clint Gibler’s chats:

    * [Jason Chan on the Origins of the Paved Road](https://www.youtube.com/watch?v=xijyr54FZn4)
    * [Netflix’s Scott Behrens on the Difficulty of Building a Useful Paved Road](https://www.youtube.com/watch?v=uQaWfTwAWp0)

7. Resourcely’s open-source project \- [Cloud Guardrails](https://www.cloudguardrails.com/) 
