# Implementing CNAPP: Day 2 Focus Areas

In the first part of the Cloud-Native Application Protection Platform (CNAPP) blog ([here](https://naman16.github.io/cloud-security/)), I laid out my thoughts on tool selection criteria and day 1 focus areas. In this blog, I want to double-click into the day 2 focus areas that include pre-deployment security, implementing CNAPP capabilities beyond Cloud Security Posture Management (CSPM), designing issues management workflows, and integrating CNAPP with enterprise tools. Below is the high-level structure of how this document is organized:

1. [Pre-Deployment Security Capabilities](#pre-deployment-security-capabilities)  
2. [Capabilities Beyond CSPM](#capabilities-beyond-cspm)  
3. [Operational Workflows and Technology Integrations](#operational-workflows-and-technology-integrations)

## Pre-Deployment Security Capabilities

In the context of CNAPP, "pre-deployment" security encompasses a range of capabilities integrated into CI/CD pipelines and the overall development lifecycle to identify and block insecure resources from reaching cloud environments. Often, I have noticed that this term is narrowly defined to apply only to production environments. However, in my experience, a broader interpretation of this term—viewing it as applicable to all stages before cloud deployment, i.e., “before reaching cloud environments”—is more effective. This allows you to shift left and roll out capabilities in a standardized manner rather than managing disparate processes across different environments. Additionally, you can then implement policy thresholds that enforce stricter security requirements in higher environments compared to lower environments to provide the necessary freedom needed for experimentation, development, and testing. Below are the primary pre-deployment capabilities:

1. [Infrastructure-as-Code (IaC) and Secret Scanning](#iac-and-secret-scanning)  
2. [Container Image Scanning and Software Composition Analysis (SCA)](#container-image-scanning-and-sca)

### IaC and Secret Scanning

This involves scanning resource deployment files—such as Terraform, CloudFormation, ARM templates, Ansible playbooks, Kubernetes manifests, Helm charts, and Dockerfiles—to identify misconfigurations and exposed secrets. Below are some key considerations for implementing IaC and secret scanning: 

* **Scaling Across CI / CD Pipelines:** In a cloud world where decentralized operating models are predominant, teams have autonomy over their development processes which leads to the proliferation of diverse pipelines, creating a complex landscape for security integration. This is because:
     * Teams often utilize various CI/CD tools—such as Jenkins, GitHub Actions, Azure DevOps, etc.—each with distinct configurations and execution environments. Additionally, in large enterprises, the sheer volume of pipelines, often numbering in the hundreds or thousands, significantly increases the number of points that require security integration. This diversity complicates the enforcement of consistent scanning practices, as each pipeline may necessitate a customized approach to effectively implement IaC and secret scanning.
     * Moreover, the decentralized nature of pipeline management means that security teams often lack visibility into all existing pipelines, making it challenging to ensure comprehensive coverage. The variety in pipeline configurations also complicates the task of standardizing scanning tools and processes, as what works for one pipeline might not be compatible with another.


    To address CI / CD scalability challenges, consider the following:
  
     * _Standardize CI / CD Toolchain:_ Collaborate with your peers in the engineering teams and build a business case for standardizing on a subset of CI / CD technologies and seek executive buy-ins. Focus on non-security benefits to gain traction and drive the message home. For example, "Implementing a unified set of tools across teams improves collaboration and knowledge sharing, as all members work with the same processes and technologies. This standardization also leads to faster onboarding of new team members and easier skill transfer between projects, as there's only one set of tools to learn. Furthermore, a standardized toolchain reduces complexity and operational friction, simplifying maintenance and support while potentially leading to cost savings through consolidated licensing and training."
     * _Maintain Security Integration Toolkit:_ Develop and maintain a central repository of integration scripts and configurations for the approved CI/CD pipeline technologies, making it easier to implement security scanning consistently. Include clear guidelines and documentation to facilitate increased adoption by engineering teams. Ensure the repository is regularly updated to incorporate new CI/CD technologies or vendor updates.

* **Preventing Bypass of Scanning Workflows:** Due to the decentralized operating model for cloud, application and DevOps teams often persist admin privileges over their respective pipelines. This can pose challenges for enforcing scanning, as these teams can disable or bypass scanning steps. Therefore, when implementing scanning across the organization, it is crucial to design processes and solutions that minimize or restrict bypasses, ideally requiring security approval for any exceptions. Below are key considerations for this:
     * _Lockdown Important Touchpoints:_
        * Isolate essential actions, such as deploying cloud resources or pushing images to registries, into reusable pipelines or workflows that are secured and can only be modified by a limited group of individuals. This ensures control over the critical touchpoints in the DevOps processes.
        * Establish access controls so that deployments or image pushes can only occur through these tightly managed reusable workflows.
        * Integrate security scanning and other requirements directly into these reusable workflows to ensure that necessary security measures are in place, making it difficult for teams to bypass security scans.
     * _Leverage Native CI / CD Pipeline Capabilities:_
        * Modern CI/CD platforms (e.g., Harness) offer policy management capabilities that allow organizations to define and enforce standardized practices across how their pipelines are created, managed, and executed. Leverage this policy-as-code feature to enforce security scanning (and any other requirements) as “required steps” that need to be embedded for the successful creation and execution of pipelines. This provides reasonable assurance that pipelines are created with the necessary security guardrails.

* **Set Different Policies for Different Environments:** Blanket security requirements (e.g., all critical, high, and medium issues must be remediated) can cause friction when enforced in lower environments as this inhibits developer productivity and increases the remediation burden for them. As such, it is advisable to have policies that have environmental context baked into them. For example, I have seen successful adoption of policies along the lines of:
     * Dev & Test Environments —> No critical issues
     * Stg / Pre-Prod Environments —> No critical and high issues
     * Prod Environments —> No critical, high, and medium issues


    There’s potential for further granularity here based on factors such as workload type, business criticality, data sensitivity, and regulatory requirements. Another example I have seen for organizations running regulated workloads:
  
     * _Non-Regulated Workloads:_
          * Dev & Test Environments —> No critical issues
          * Stg / Pre-Prod Environments —> No critical and high issues
          * Prod Environments —> No critical, high, and medium issues 
     * _Regulated Workloads:_
          * Dev & Test Environments —> No critical and high issues
          * Stg / Pre-Prod Environments —> No critical, high, and medium issues
          * Prod Environments —> No critical, high, and medium issues
  
### Container Image Scanning and SCA

This includes scanning your container images and software packages during the build stage to identify vulnerabilities, misconfigurations, exposed secrets, etc.. The key considerations for image scanning and SCA are similar to the ones listed above for IaC & secret scanning. 

## Capabilities Beyond CSPM

As a recap from the previous blog, I expanded the definition of CSPM to include core CSPM because they are relatively straightforward to implement, deliver quick value, and have a similar path to operationalization. In this section, I will focus on the additional capabilities of CNAPP that build upon the insights and lessons learned \- such as high-risk areas, cloud environment setup, landing zone design, naming conventions, tagging standards, etc. \- from operationalizing CSPM. Below are some of the core CNAPP capabilities that extend beyond CSPM:

1. [Registry Scanning](#registry-scanning)  
2. [Cloud Infrastructure Entitlement Management (CIEM), Data Security Posture Management (DSPM) and Attack Surface Management](#ciem-dspm-and-attack-surface-management)  
3. [Container and Kubernetes Security](#container-and-kubernetes-security)  
4. [Cloud Detection and Response (CDR)](#cloud-detection-and-response-cdr)

### Registry Scanning

This includes scanning your container registries to detect vulnerabilities and malware on images. This enables you to have visibility into images that:

* Have been pushed to the registries outside of the standard CI / CD pipelines  
* Have been running in the environment for a long period and have become vulnerable after the initial scan during the build phase

If your organization uses cloud-native registries (e.g., Amazon Elastic Container Registry (ECR), Azure Container Registry (ACR)), CNAPP tools typically scan them without requiring additional configuration, as this feature is usually enabled by default during the initial setup. However, if you are utilizing a third-party registry (e.g., JFrog Artifactory), further configurations may be necessary for scanning. Below are key considerations for registry scanning:

* **Managing Volume of Issues:** The number of issues identified can be quite substantial, as registries can become chaotic for several reasons:
    * Teams may push numerous images and packages while only utilizing a small fraction of those for their workloads.
    * The lack of a well-defined registry structure can make it difficult to track ownership and accountability.
    * Registry access can be left widely open (i.e. no RBAC), allowing anyone to push to any location within the registry.
      
      Given these challenges, it is essential to invest efforts in correlating issues with actual running containers and workloads and prioritizing them for remediation, rather than requiring remediation for all identified issues.

* **Assigning Remediation Ownership:** The approach to assigning remediation ownership can vary significantly depending on your organization’s operating model, due to the layered nature of containers.
    * If your organization has a central team (e.g., cloud engineering) responsible for maintaining golden base images (the base layer) that application and DevOps teams build upon with their specific layers, then it is essential to trace the issue back to the vulnerable layer and assign remediation ownership accordingly.
        * If the issue lies within the base layer, the effort required for remediation across the entire environment increases significantly for the following reasons:
            * The central team must update or create a new golden base image that includes the fix.
            * The consuming teams (i.e., application and DevOps teams) will need to redeploy their applications and workloads using this updated base layer.

              Doing this regularly requires organizations to have mature DevOps processes where teams understand the importance and need to constantly rehydrate their images. Furthermore, there should be good testing and dependency management programs in place to ensure that applications are thoroughly tested before these updates are released to production and that base image modifications do not cause any disruptions.
          
        * If the issue is associated with the application layer, then the responsibility lies with the respective application / DevOps teams to remediate and redeploy their application / workload images. The operations around this are relatively easier because the burden lies exclusively with the application / DevOps teams and there are no dependencies on an enterprise team.
          
    * If your organization’s setup is one where the concept of golden images does not exist and the application / DevOps teams own the entire lifecycle of the container images, then the ownership assignment and operations are similar to the previous point about managing issues at the application layer.

### CIEM, DSPM, and Attack Surface Management

Although these are all broad and disparate categories, I have grouped them under one section because the approach to operationalizing each of these capabilities is similar. Once you are able to operationalize one capability, the strategy and process for the rest of the areas will be comparable. Below are the key considerations for these capabilities:

* **Current-State Understanding:** If a comprehensive discovery exercise regarding current processes, environment setup, landing zone design, and other factors has not yet been conducted as part of operationalizing CSPM, it should be prioritized as the first step in expanding into these CNAPP areas. Below are example questions to give you insights into the kind of understanding that should be developed:
    * What is the tagging standard in place, and how well is it adopted? Does the standard include details such as resource owner, application owner, and data classification?
    * What is the naming convention for resources, and is it applied consistently? For example, Is there a clear method for distinguishing between cloud admin resources, developer resources, and security resources?
    * Who is responsible for managing the lifecycle of the different roles and how is it done?
    * What are the different 3rd parties that are expected to have access to the cloud environments?
    * Is there a comprehensive asset inventory that tracks various subscriptions, accounts, and projects known or expected to have publicly exposed endpoints or sensitive data sources?
    * What does the networking setup look like, and what approved patterns are in place for publicly exposing endpoints?

* **Custom Developing & Fine-Tuning Policies:** Out-of-the-box (OOB) CNAPP policies are valuable for establishing a baseline understanding of the different types of detections available / possible. However, they lack the necessary context around the setup of the cloud environment to distinguish between different types of resources and accurately detect issues \- such as over-permissive roles (cloud admin roles (expected) v/s EC2 instance roles (not expected)), presence of sensitive data sources (S3 bucket in regulated production account containing PII (expected) v/s S3 bucket in development containing PII (not expected)), and externally exposed endpoints (ALB in a production account expected to have internet exposure (expected) v/s ALB in development account (not expected)). Simply enabling these policies without any customization or fine-tuning can lead to false positives or a high volume of risk exceptions. Therefore, it is essential to prioritize customization and fine-tuning from the outset when operationalizing these CNAPP areas. Below are some of the customizations you should consider applying:
    * Use the baseline CNAPP policies as a starting point and
        * Leverage resource tags, resource names, and accounts / subscription information to apply filtering on the base policies so that context-unaware requirements are not enforced (e.g., it is expected for cloud admins to have excessive (or admin) privileges in the environment but not for EC2 instance roles)
        * Customize / modify the specific logic to tailor to your standards (e.g., if your organization's policy for inactive roles is 120 days instead of the OOB CNAPP policy of 90 days, then customize the policies accordingly).
    * Develop a prioritized backlog of requirements and implement custom policies to identify violations to the design patterns that you have defined as an organization (e.g., resources in development should not access resources in production, resources in development should not be publicly exposed, resources in development should not contain sensitive data, etc.)


        Below are some examples to further illustrate the intent behind customization / fine-tuning of CNAPP policies:
  
        * Identify all storage buckets and database instances containing PII, PCI, or PHI data that are missing the tag/label “Data Classification: Sensitive.”
        * Identify all storage buckets and database instances with PII, PCI, or PHI data that belong to the development or test Organizational Unit (OU).
        * Identify all roles that do not have the name “cloud-admin-roles” but possess admin privileges.
        * Identify all publicly exposed resources that do not belong to the subscription/account labeled “external-access-account."

* **Correlating Findings Across Different CNAPP Areas:** Once you have familiarized yourself with the environment and have some experience in developing CNAPP policies across the above mentioned different areas, you can develop more complex detections that string together issues from the different capability areas to uncover more interesting insights. Some examples include:
    * IAM roles in the development OU have cross-account access to roles in production OU which have admin privileges on storage buckets or database instances that have sensitive data
    * Lambda functions are publicly exposed and have administrative privileges on cloud-admin-roles
    * Lambda functions are publicly exposed and contain critical vulnerabilities with known public exploit

### Container and Kubernetes Security:

This section addresses capabilities focused on securing actively running containerized workloads and Kubernetes clusters, specifically Cloud Workload Protection Platform (CWPP), Kubernetes Security Posture Management (KSPM), and Kubernetes Admissions Controller. It does not encompass capabilities like helm chart/Kubernetes manifest file scanning, Dockerfile scanning, and container image scanning, as these are more “pre-deployment” and have already been discussed above. Additionally, the rationale for grouping these capabilities is that they are simalar to deployment of security agents (e.g., EDR, SIEM forwarders, etc.) in that they need to be enabled on a per container, node, or cluster level. This decentralized approach can lead to increased operational complexity when scaling these capabilities across large platform footprints. Below are some key considerations for ensuring the runtime security of containers and Kubernetes clusters:

* **Prioritize Critical Workloads:** Implementing these capabilities across the entire organization can become a high-touch effort, especially if multiple teams serve as platform admins for their respective applications or business units. Therefore, consider focusing the rollout of these capabilities on a prioritized set of workloads or clusters instead of attempting to cover all containers or clusters. The strategy for identifying prioritized workloads will vary by organization, but production workloads, business critical workloads, externally exposed workloads, and those interacting with sensitive data are good candidates for prioritization.  
* **Maintain Deployment Templates:** For all the different flavors of orchestration platforms that are in-scope, develop and maintain instruction sets, guidance materials, and deployment scripts that can be readily used by the platform teams to deploy the KSPM connectors, admissions controllers, and CWPP sensors / agents. Additionally, ensure these artifacts are regularly updated to align with vendor releases and upgrades.

### Cloud Detection and Response (CDR)

This is a relatively newer area for CNAPP that includes capabilities such as malware and threat detection, cloud events analysis, forensics collection, and automated responses. While I have primarily engaged in proofs-of-concept, utilizing the platform for initial investigations and information gathering, and deploying automated responses for simple use cases (such as quarantining resources, blocking public access, enabling encryption, upgrading EC2 instances to IMDSv2, etc.), I am excited to see how this field evolves. The integration of cloud events and CNAPP detection within a single platform seems very powerful. This will give us the ability to potentially start developing policies that are based on actual activities that are happening in the cloud environments coupled with the visibility and context that a CNAPP tool can provide. This could help offload some of the query development that otherwise happens within SIEM platforms, positioning CNAPP as the first line of detection and alerting. These alerts can then be forwarded to SIEM for further correlation and analysis. This approach has the added advantage of relying on the cloud security team’s expertise and understanding of the environment,  potentially resulting in more accurate alerts and fewer false positives. Below are example use-cases that could be possible by integrating cloud events with CNAPP:

* Identify all cloud IAM roles in development OU that attempted to access roles in production OU  
* Identify all cloud IAM roles that attempted to access buckets and database instances with sensitive data and had a high (above 70%) failure rate  
* Identify all cloud IAM roles that performed read actions on a high (above 15\) number of services in the production OU in the last 24 hours  
* Identify all EC2 instances that are publicly exposed and attempted to create an IAM user with access keys and admin privileges

## Operational Workflows and Technology Integrations

Operational workflows and technology integrations are important in ensuring that the insights generated by CNAPP tools are actioned efficiently and timely, thereby bridging the gap between identifying security issues and practical risk mitigation. This involves aspects such as:

* Defining remediation requirements by environment and criticality (see details in section [IaC and Secret Scanning](#iac-and-secret-scanning))
* Classifying issues and routing them to the appropriate remediation owners  
* Setting up integrations with existing tools and workflows  
* Providing remediation support  
* Reporting on SLA compliance and overall security posture

While the specific workflows and integrations will differ for each organization based on factors such as size, existing toolchain, cloud and DevOps maturity, release and change management processes, etc., my experience working with various organizations around the operationalization of CNAPP issues has revealed the below key principles:

* Focus on developing solutions that are “good enough” and work for your organization rather than overengineering to build the perfect workflows and integrations.   
* Foster a partnership with application and development teams by meeting them halfway in how they prefer to receive issue communications (e.g., email, Teams, Jira, Slack).  
* Avoid imposing your ideal scenario on them. This doesn’t mean accommodating every tool; rather, concentrate on the tools your organization predominantly uses and allow teams to choose their preferences from that list.  
* Continuously seek feedback from the teams to enhance processes and integrations accordingly.

Below is a visual that provides a high-level overview of classifying different types of issues, identifying responsible stakeholders, and setting up integrations for effective communication, tracking, and management of issues:  

![CNAPP Workflows & Integrations](/images/CNAPP%20Workflows%20&%20Integrations.png)

In summary, addressing day 2 focus areas for CNAPP is essential for maximizing ROI and enhancing the overall maturity of the cloud security program. Prioritizing pre-deployment security capabilities \- such as IaC, secret, and container image scanning \- ensures vulnerabilities and misconfigurations are identified and remediated early in the development lifecycle, conserving valuable time and resources. By operationalizing capabilities beyond traditional CSPM, organizations gain increased visibility into critical security domains, including identity and access management, data security, network protection, attack surface management, container and workload security, and threat detection and response. Establishing clear operational workflows and integrating with existing tools \- such as ticketing and messaging platforms \- transforms security insights into actionable information that can be seamlessly incorporated into daily processes. 

Ultimately, organizations must commit to continually updating their capabilities to stay ahead of a dynamic threat landscape, recognizing that CNAPP implementation is a journey, not a one-time event. A journey that requires organizations to always be on the frontfoot and constantly update and improve existing capabilities, implement new capabilities, and seek operational efficiencies to mitigate risks and adapt to emerging threats with reasonable assurance.

PS: CNAPP is a constantly evolving area where new capabilities are introduced regularly. The most recent announcement that made news was Wiz's release of "[Wiz Code](https://www.wiz.io/blog/wiz-code-enhances-aspm-with-code-to-cloud-context)" that seeks to combine DevSecOps, Application Security Application Security Posture Management (ASPM), and CNAPP capabilities into a singular platform to provide unified visibility and security from “code-to-cloud”. However, the intent of this blog is to focus on the core CNAPP capabilities that are available across most vendors.
