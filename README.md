# DevSecOps Process and ToolStack 2021


**DevSecOps info:** 

This is to give a highlevel overview of DevSecOps and its processes. This also covers some of the industries best tools for DevSecOps implementstions.
 
 ![Alt text](IMG/DevSecOps_banner.jpg?raw=true "DevSecOps_Banner")

# Table of Contents

- [Defintition](#what-is-devsecops)
- [Tooling](#tooling)
- [Precommit and threat modeling](#pre-commit-time-tools)
- [SAST](#sast)
- [DAST](#dast)
- [Supply chain and dependencies](#oss-and-dependecy-management)
- [Infrastructure as code](#infrastructure-as-code-security)
- [Containers security](#containers) 
- [Kubernetes](#kubernetes) 
- [Cloud](#multi-cloud)
- [Chaos engineering](#chaos-engineering)
- [Policy as code](#policy-as-code)
- [Methodologies](#methodologies-whitepapers-and-architecture) 

# What is DevSecOps 
DevSecOps fosuses on security automation, testing and enforcement during DevOps - Release - SDLC cycles. The whole meaning behind this methodology is connecting together Development, Security and Operations. DevSecOps is methodology providing diffeent methods, techniess and processes backed mainly with tooling focusing on developer / secuirty experience. 

DevSecOps takes care that security is part of every stage of DevOps loop - Plan, Code, Build, Test, Release, Deploy, Operate, Monitor. 

Various definitions: 
* https://www.redhat.com/en/topics/devops/what-is-devsecops
* https://www.ibm.com/cloud/learn/devsecops 
* https://snyk.io/series/devsecops/ 
* https://www.synopsys.com/glossary/what-is-devsecops.html

# Tooling

## Pre-commit time tools

In this section you can find lifecycle helpers, precommit hook tools and threat modeling tools. Threat modeling tools are specific category by themselves allowing you simulate and dicover potential gaps before you start to develop the software or during the process.

Modern DevSecOps tools allow to use Threat modeling as code or generation of threat models based on the existing code annotations. 

| Name | URL | Description | 
| :---------- | :---------- | :---------- | 
| **git-secrets** | [https://github.com/awslabs/git-secrets](https://github.com/awslabs/git-secrets) | AWS labs tool preventing you from committing secrets to a git repository  |
| **git-hound** | [https://github.com/tillson/git-hound](https://github.com/tillson/git-hound) | Seachers secrets in git |
| **goSDL** | [https://github.com/slackhq/goSDL](https://github.com/slackhq/goSDL) |Security Development Lifecycle checklist   |
| **ThreatPlaybook** | [https://github.com/we45/ThreatPlaybook](https://github.com/we45/ThreatPlaybook) |Threat modeling as code   |
| **Threat Dragon** | [https://github.com/OWASP/threat-dragon](https://github.com/OWASP/threat-dragon) | OWASP Threat modeling tool  |
| **threatspec** | [https://github.com/threatspec/threatspec](https://github.com/threatspec/threatspec) | Threat modeling as code  |
| **pytm** | [https://github.com/izar/pytm](https://github.com/izar/pytm) | A Pythonic framework for threat modeling  |
| **Threagile** | [https://github.com/Threagile/threagile](https://github.com/Threagile/threagile) | A Pythonic framework for threat modeling  |
| **MAL-lang** | [https://mal-lang.org/#what ](https://mal-lang.org/#what ) | A language to create cyber threat modeling systems for specific domains  |
| **Microsoft Threat modleing tool** | [https://docs.microsoft.com/en-us/azure/security/develop/threat-modeling-tool](https://docs.microsoft.com/en-us/azure/security/develop/threat-modeling-tool) | Microsoft threat modeling tool  |
| **Talisman** | [https://github.com/thoughtworks/talisman](https://github.com/thoughtworks/talisman) | A tool to detect and prevent secrets from getting checked in |
| **SEDATED** | [https://github.com/OWASP/SEDATED](https://github.com/OWASP/SEDATED) | The SEDATED® Project (Sensitive Enterprise Data Analyzer To Eliminate Disclosure) focuses on preventing sensitive data such as user credentials and tokens from being pushed to Git. |
| **Sonarlint** | [https://github.com/SonarSource/sonarlint-core](https://github.com/SonarSource/sonarlint-core) |  Sonar linting utility for IDE |
| **DevSkim** | [https://github.com/microsoft/DevSkim](https://github.com/microsoft/DevSkim) |  DevSkim is a framework of IDE extensions and language analyzers that provide inline security analysis |
| **detect-secrets** | [https://github.com/Yelp/detect-secrets](https://github.com/Yelp/detect-secrets) |  Detects secrets in your codebase |

## Secrets management 
Secrets management includes managing, versioning, encrypting, discovery, rotating, provisioning of passwords, certificates, configuration values and other types of secrets. 

| Name | URL | Description | 
| :---------- | :---------- | :---------- | 
| **GitLeaks** | [https://github.com/zricethezav/gitleaks](https://github.com/zricethezav/gitleaks) | Gitleaks is a scanning tool for detecting hardcoded secrets  |
| **TruffleHog** | [https://github.com/trufflesecurity/truffleHog](https://github.com/trufflesecurity/truffleHog) | TruffleHog is a scanning tool for detecting hardcoded secrets  |
| **Hashicorp Vault** | [https://github.com/hashicorp/vault](https://github.com/hashicorp/vault) | Hashicorp Vault secrets management  |
| **Mozilla SOPS** | [https://github.com/mozilla/sops ](https://github.com/mozilla/sops ) | Mozilla Secrets Operations  |
| **AWS secrets manager GH action** | [https://github.com/marketplace/actions/aws-secrets-manager-actions](https://github.com/marketplace/actions/aws-secrets-manager-actions)| AWS secrets manager [docs](https://aws.amazon.com/secrets-manager/) | 
| **GitRob** | [https://github.com/michenriksen/gitrob](https://github.com/michenriksen/gitrob) | Gitrob is a tool to help find potentially sensitive files pushed to public repositories on Github  |
| **git-wild-hunt** | [https://github.com/d1vious/git-wild-hunt](https://github.com/d1vious/git-wild-hunt ) | A tool to hunt for credentials in the GitHub |
| **aws-vault** | [https://github.com/99designs/aws-vault](https://github.com/99designs/aws-vault) | AWS Vault is a tool to securely store and access AWS credentials in a development environment |
| **Knox** | [https://github.com/pinterest/knox](https://github.com/pinterest/knox) | Knox is a service for storing and rotation of secrets, keys, and passwords used by other services |
| **Chef vault** | [https://github.com/chef/chef-vault](https://github.com/chef/chef-vault) |  allows you to encrypt a Chef Data Bag Item |
| **Ansible vault** | [Ansible vault docs](https://docs.ansible.com/ansible/latest/cli/ansible-vault.html#ansible-vault) |  Encryption/decryption utility for Ansible data files |

## OSS and Dependecy management

Dependecny security testing and analysis is very important part of disocvering supply chain attacks. SBOM creation and following depenceny scanning (Software composition analysis) is critical part of Continuous integration. Data series and data trends tracking should be part of CI tooling. You need to know what you produce and what you consume in context of libraries and packages. 

| Name | URL | Description | 
| :---------- | :---------- | :---------- | 
| **CycloneDX** | [https://github.com/orgs/CycloneDX/repositories](https://github.com/orgs/CycloneDX/repositories) | CycloneDX format for **SBOM** | 
| **Snyk** | [https://github.com/snyk/snyk](https://github.com/snyk/snyk) | Snyk scans and monitors your projects for security vulnerabilities |
| **vulncost** | [https://github.com/snyk/vulncost](https://github.com/snyk/vulncost) | Security Scanner for VS Code |
| **Dependency Combobulator** | [https://github.com/apiiro/combobulator](https:/github.com/apiiro/combobulator) | Dependency-related attacks detection and prevention through heuristics and insight engine (support multiple dependency schemes) | 
| **DependencyTrack** | [https://github.com/DependencyTrack/dependency-track](https://github.com/DependencyTrack/dependency-track) | Dependency security tracking platfrom |
| **DependencyCheck** | [https://github.com/jeremylong/DependencyCheck](https://github.com/jeremylong/DependencyCheck) | Simple dependecny security scanner good for CI |
| **Retire.js** | [https://github.com/retirejs/retire.js/](https://github.com/retirejs/retire.js/) | Helps developers to detect the use of JS-library versions with known vulnerabilities |
| **PHP security checker** | [https://github.com/fabpot/local-php-security-checker](https://github.com/fabpot/local-php-security-checker) | Check vulnerabilities in PHP dependecies | 
| **bundler-audit** | [https://github.com/rubysec/bundler-audit](https://github.com/rubysec/bundler-audit) | Patch-level verification for bundler | 
| **gemnasium** | [https://gitlab.com/gitlab-org/security-products/analyzers/gemnasium ](https://gitlab.com/gitlab-org/security-products/analyzers/gemnasium ) | Dependency Scanning Analyzer based on Gemnasium | 
| **Dependabot** | [https://github.com/dependabot/dependabot-core](https://github.com/dependabot/dependabot-core) | Automated dependency updates built into GitHub providign security alerts |
| **npm-check** | [https://www.npmjs.com/package/npm-check](https://www.npmjs.com/package/npm-check) | Check for outdated, incorrect, and unused dependencies. |

## Supply chain specific tools 

Supply chain is often target of attacks. Which libraries you use can have massive impact on security of final product (artifacts). CI (Continous integration must be monitored inside the taks and jobs in pipeline steps. Integrity checks must be stored out od the system and in ideal case several validation runs with comparison of integry hashes / or attestation must be performed. 

| Name | URL | Description | 
| :---------- | :---------- | :---------- | 
| **Tekton chains** | [https://github.com/tektoncd/chains](https://github.com/tektoncd/chains/) | Kubernetes Custom Resource Definition (CRD) controller that allows you to manage your supply chain security in Tekton. | 
| **in-toto** | [https://github.com/in-toto/attestation/tree/v0.1.0/spec](https://github.com/in-toto/attestation/tree/v0.1.0/spec) | An in-toto attestation is authenticated metadata about one or more software artifacts |
| **SLSA** | [Official GitHub link](https://github.com/slsa-framework/slsa/blob/main/docs/index.md ) | Supply-chain Levels for Software Artifacts |


https://github.com/in-toto/attestation/tree/v0.1.0/spec 
https://github.com/slsa-framework/slsa/blob/main/docs/index.md 



## SAST

Static code review tools working with source code and looking for known patterns and relationships of methods, variables, classes and libriaries. SAST works with the raw code and usualy not with build packages. 

| Name | URL | Description | 
| :---------- | :---------- | :---------- |
| **Brakeman** | [https://github.com/presidentbeef/brakeman](https://github.com/presidentbeef/brakeman) | Brakeman is a static analysis tool which checks Ruby on Rails applications for security vulnerabilities|
| **Semgrep** | [https://semgrep.dev/](https://semgrep.dev/) | Hi-Quality Open source, works on 17+ languages |![Semgrep](https://img.shields.io/github/stars/returntocorp/semgrep?style=for-the-badge) | 
| **Bandit** | [https://github.com/PyCQA/bandit ](https://github.com/PyCQA/bandit ) | Python specific SAST tool |![Bandit](https://img.shields.io/github/stars/PyCQA/bandit?style=for-the-badge) | 
| **libsast** | [https://github.com/ajinabraham/libsast ](https://github.com/ajinabraham/libsast ) | Generic SAST for Security Engineers. Powered by regex based pattern matcher and semantic aware semgrep |
| **ESLint** | [https://eslint.org/](https://eslint.org/) | Find and fix problems in your JavaScript code | | 
| **nodejsscan** | [https://github.com/ajinabraham/nodejsscan](https://github.com/ajinabraham/nodejsscan) | NodeJs SAST scanner with GUI |
| **FindSecurityBugs** | [https://find-sec-bugs.github.io/](https://find-sec-bugs.github.io/) | The SpotBugs plugin for security audits of Java web applications | 
| **SonarQube community** | [https://github.com/SonarSource/sonarqube](https://github.com/SonarSource/sonarqube) | Detect security issues in code review with Static Application Security Testing (SAST) |
| **gosec** | [https://github.com/securego/gosec](https://github.com/securego/gosec) | Inspects source code for security problems by scanning the Go AST. |

OWASP curated list of SAST tools : https://owasp.org/www-community/Source_Code_Analysis_Tools 

## DAST

Dynamic application security testing (DAST) is a type of application testing (in most cases web) that checks your application from the outside by active communication and analysis of the responses based on injected inputs. DAST tools rely on inputs and outputs to operate. A DAST tool uses these to check for security problems while the software is actually running and is actively deploed on the server (or serverless function).

| Name | URL | Description |
| :---------- | :---------- | :---------- | 
| **Zap proxy** | [https://owasp.org/www-project-zap/](https://owasp.org/www-project-zap/) | Zap proxy providing various docker containers for CI/CD pipeline|
| **Wapiti** | [https://github.com/wapiti-scanner/wapiti ](https://github.com/wapiti-scanner/wapiti ) | Light pipeline ready scanning tool |
| **Nuclei** | [https://github.com/projectdiscovery/nuclei](https://github.com/projectdiscovery/nuclei) | Template based security scanneing tool |
| **purpleteam** | [https://github.com/purpleteam-labs/purpleteam](https://github.com/purpleteam-labs/purpleteam) | CLI DAST tool incubator project |
| **oss-fuzz** | [https://github.com/google/oss-fuzz ](https://github.com/google/oss-fuzz ) | OSS-Fuzz: Continuous Fuzzing for Open Source Software |
| **nikto** | [https://github.com/sullo/nikto](https://github.com/sullo/nikto) | Nikto web server scanner |
| **skipfish** | [https://code.google.com/archive/p/skipfish/](https://code.google.com/archive/p/skipfish/) | Skipfish is an active web application security reconnaissance tool|

## Kubernetes 

| Name | URL | Description | 
| :---------- | :---------- | :---------- | 
| **KubiScan** | [https://github.com/cyberark/KubiScan](https://github.com/cyberark/KubiScan) | A tool for scanning Kubernetes cluster for risky permissions |
| **Kubeaudit** | [https://github.com/Shopify/kubeaudit](https://github.com/Shopify/kubeaudit) | Audit Kubernetes clusters for various different security concerns |
| **Kubescape** | [https://github.com/armosec/kubescape](https://github.com/armosec/kubescape) |  The first open-source tool for testing if Kubernetes is deployed according to the NSA-CISA and the MITRE ATT&CK®. |
| **kubesec** | [https://github.com/controlplaneio/kubesec](https://github.com/controlplaneio/kubesec) | Security risk analysis for Kubernetes resources |
| **kube-bench** | [https://github.com/aquasecurity/kube-bench ](https://github.com/aquasecurity/kube-bench ) | Kubernetes benchmarking tool|
| **kube-score** | [https://github.com/zegl/kube-score](https://github.com/zegl/kube-score) | Static code analysis of your Kubernetes object definitions |
| **kube-hunter** | [https://github.com/aquasecurity/kube-hunter](https://github.com/aquasecurity/kube-hunter) | Active scanner for k8s (purple)  |
| **Calico** | [https://github.com/projectcalico/calico](https://github.com/projectcalico/calico) | Calico is an open source networking and network security solution for containers  |
| **Kyverno** | [https://github.com/kyverno/kyverno/](https://github.com/kyverno/kyverno) | Kyverno is a policy engine designed for Kubernetes |
| **Krane** | [https://github.com/appvia/krane](https://github.com/appvia/krane) | Simple Kubernetes RBAC static analysis tool | 
| **Starboard** | [https://github.com/aquasecurity/starboard](https://github.com/aquasecurity/starboard ) | Starboard inegrates security tools by outputs into Kubernetes CRDs |
| **Gatekeeper** | [https://github.com/open-policy-agent/gatekeeper](https://github.com/open-policy-agent/gatekeeper) | Open policy agent gatekeeper for k8s |
| **Inspektor-gadget** | [https://github.com/kinvolk/inspektor-gadget](https://github.com/kinvolk/inspektor-gadget ) | Collection of tools (or gadgets) to debug and inspect k8s | 
| **kube-linter** | [https://github.com/stackrox/kube-linter ](https://github.com/stackrox/kube-linter) | Static analysis for Kubernetes |

## Containers 

| Name | URL | Description | 
| :---------- | :---------- | :---------- |
| **Harbor** | [https://github.com/goharbor/harbor](https://github.com/goharbor/harbor) | Trusted cloud native registry project|
| **Anchore** | [https://github.com/anchore/anchore-engine](https://github.com/anchore/anchore-engine) | Centralized service for inspection, analysis, and certification of container images |
| **Clair** | [https://github.com/quay/clair](https://github.com/quay/clair) | Docker vulnerability scanner|
| **Deepfence ThreatMapper** | [https://github.com/deepfence/ThreatMapper](https://github.com/deepfence/ThreatMapper) | Apache v2, powerful runtime vulnerability scanner for kubernetes, virtual machines and serverless. |
| **Docker bench** | [https://github.com/docker/docker-bench-security ](https://github.com/docker/docker-bench-security ) | Docker benchmarking agaist CIS|
| **Falco** | [https://github.com/falcosecurity/falco](https://github.com/falcosecurity/falco) | Container runtime protection |
| **Trivy** | [https://github.com/aquasecurity/trivy](https://github.com/aquasecurity/trivy) | Comprehensive scanner for vulnerabilities in container images |
| **Notary** | [https://github.com/notaryproject/notary](https://github.com/notaryproject/notary) | Docker signing|
| **Cosign** | [https://github.com/sigstore/cosign](https://github.com/sigstore/cosign) | Container signing|
| **watchtower** | [https://github.com/containrrr/watchtower](https://github.com/containrrr/watchtower) | Updates the running version of your containerized app |



## Multi-Cloud 

| Name | URL | Description |
| :---------- | :---------- | :---------- |
| **Cloudsploit** | [https://github.com/aquasecurity/cloudsploit](https://github.com/aquasecurity/cloudsploit) | Detection of security risks in cloud infrastructure |
| **ScoutSuite** | [https://github.com/nccgroup/ScoutSuite](https://github.com/nccgroup/ScoutSuite) | NCCgroup mutlicloud scanning tool |
| **CloudCustodian** | [https://github.com/cloud-custodian/cloud-custodian/](https://github.com/cloud-custodian/cloud-custodian/) | Multicloud security analysis framework |

## AWS 

AWS specific DevSecOps tooling. Tools here coverdifferent areas like inventory management, misconfiguration scanning or IAM roles and policies review. 

| Name | URL | Description | 
| :---------- | :---------- | :---------- | 
| **Dragoneye** | [https://github.com/indeni/dragoneye](https://github.com/indeni/dragoneye) | Dragoneye Indeni AWS scanner |
| **Prowler** | [https://github.com/toniblyx/prowler](https://github.com/toniblyx/prowler) | Prowler is a command line tool that helps with AWS security assessment, auditing, hardening and incident response. |
| **aws-inventory** | [https://github.com/nccgroup/aws-inventory](https://github.com/nccgroup/aws-inventory) | Helps to discover all AWS resources created in an account|
| **PacBot** | [https://github.com/tmobile/pacbot](https://github.com/tmobile/pacbot) | Policy as Code Bot (PacBot)|
| **Komiser** | [https://github.com/mlabouardy/komiser](https://github.com/mlabouardy/komiser) | Monitoring dashboard for costs and security|
| **Cloudsplaining** | [https://github.com/salesforce/cloudsplaining](https://github.com/salesforce/cloudsplaining) | IAM analysis framework |
| **ElectricEye** | [https://github.com/jonrau1/ElectricEye](https://github.com/jonrau1/ElectricEye) | Continuously monitor your AWS services for configurations |
| **Cloudmapper** | [https://github.com/duo-labs/cloudmapper](https://github.com/duo-labs/cloudmapper ) | CloudMapper helps you analyze your Amazon Web Services (AWS) environments |
| **cartography** | [https://github.com/lyft/cartography](https://github.com/lyft/cartography) | Consolidates AWS infrastructure assets and the relationships between them in an intuitive graph | 
| **policy_sentry** | [https://github.com/salesforce/policy_sentry](https://github.com/salesforce/policy_sentry ) | IAM Least Privilege Policy Generator |
| **AirIAM** | [https://github.com/bridgecrewio/AirIAM](https://github.com/bridgecrewio/AirIAM) | IAM Least Privilege anmalyzer and Terraformer |
| **StreamAlert** | [https://github.com/airbnb/streamalert](https://github.com/airbnb/streamalert ) | AirBnB serverless, real-time data analysis framework which empowers you to ingest, analyze, and alert  |
| **CloudQuery** | [https://github.com/cloudquery/cloudquery/](https://github.com/cloudquery/cloudquery/) | AirBnB serverless, real-time data analysis framework which empowers you to ingest, analyze, and alert  | 
| **S3Scanner** | [https://github.com/sa7mon/S3Scanner/](https://github.com/cloudquery/cloudquery/) | A tool to find open S3 buckets and dump their contents  |
| **aws-iam-authenticator** | [https://github.com/kubernetes-sigs/aws-iam-authenticator/](https://github.com/kubernetes-sigs/aws-iam-authenticator/) | A tool to use AWS IAM credentials to authenticate to a Kubernetes cluster |
| **kube2iam** | [https://github.com/jtblin/kube2iam/](https://github.com/jtblin/kube2iam/) | A tool to use AWS IAM credentials to authenticate to a Kubernetes cluster |
| **AWS open source security samples** | [Official AWS opensource repo](https://github.com/orgs/aws-samples/repositories?language=&q=security&sort=&type=) |Collection of official AWS open-source resources | 


## Policy as code

Policy as code is the idea of writing code in a high-level language to manage and automate policies. By representing policies as code in text files, proven software development best practices can be adopted such as version control, automated testing, and automated deployment. (Source: https://docs.hashicorp.com/sentinel/concepts/policy-as-code)

| Name | URL | Description |
| :---------- | :---------- | :---------- | 
| **Open Policy agent** | [https://github.com/open-policy-agent/opa](https://github.com/open-policy-agent/opa) | General-purpose policy engine that enables unified, context-aware policy enforcement across the entire stack |
| **Inspec** | [https://github.com/inspec/inspec](https://github.com/inspec/inspec) | Chef InSpec is an open-source testing framework for infrastructure with a human- and machine-readable language for specifying compliance, security and policy requirements. | 
| **Cloud Formation guard** | [https://github.com/aws-cloudformation/cloudformation-guard](https://github.com/aws-cloudformation/cloudformation-guard) | Cloud Formation policy as code | 


## Chaos engineering

Chaos Engineering is the discipline of experimenting on a system in order to build confidence in the system’s capability to withstand turbulent conditions in production.

Reading and manifestos: https://principlesofchaos.org/

| Name | URL | Description | 
| :---------- | :---------- | :---------- | 
| **chaos-mesh** | [https://github.com/chaos-mesh/chaos-mesh](https://github.com/chaos-mesh/chaos-mesh) | It is a cloud-native Chaos Engineering platform that orchestrates chaos on Kubernetes environments |
| **Chaos monkey** | [https://netflix.github.io/chaosmonkey/](https://netflix.github.io/chaosmonkey/) | Chaos Monkey is responsible for randomly terminating instances in production to ensure that engineers implement their services to be resilient to instance failures. |
| **chaoskube** | [https://github.com/linki/chaoskube ](https://github.com/linki/chaoskube ) | Test how your system behaves under arbitrary pod failures. |
| **Kube-Invaders** | [https://github.com/lucky-sideburn/KubeInvaders](https://github.com/lucky-sideburn/KubeInvaders) | Gamified chaos engineering tool for Kubernetes |
| **kube-monkey** | [https://github.com/asobti/kube-monkey](https://github.com/asobti/kube-monkey) | Gamified chaos engineering tool for Kubernetes |
| **Gremlin** | [https://github.com/gremlin/gremlin-python](https://github.com/gremlin/gremlin-python) | Chaos enginnering SaaS platform with free plan and some open source libraries |
| **AWS FIS samples** | [https://github.com/aws-samples/aws-fault-injection-simulator-samples](https://github.com/aws-samples/aws-fault-injection-simulator-samples) | AWS Fault injection simulator samples |
| **CloudNuke** | [https://github.com/gruntwork-io/cloud-nuke](https://github.com/gruntwork-io/cloud-nuke) | CLI tool to delete all resources in an AWS account |

## Infrastructure as code security 

Scanning your infrascructure when it is only code helps shift-left the security. Many tools offer in IDE scanning and providing real-time advisory do Cloud engineers. 

| Name | URL | Description |
| :---------- | :---------- | :---------- | 
| **KICS** | [https://github.com/Checkmarx/kics](https://github.com/Checkmarx/kics) | Checkmarx security testing opensource for IaC |
| **Checkov** | [https://github.com/bridgecrewio/checkov](https://github.com/bridgecrewio/checkov) | Checkov is a static code analysis tool for infrastructure-as-code |
| **tfsec** | [https://github.com/aquasecurity/tfsec](https://github.com/aquasecurity/tfsec) | tfsec uses static analysis of your terraform templates to spot potential security issues. Now with terraform CDK support |
| **terrascan** | [https://github.com/accurics/terrascan](https://github.com/accurics/terrascan) | Terrascan is a static code analyzer for Infrastructure as Code | 
| **cfsec** | [https://github.com/aquasecurity/cfsec](https://github.com/aquasecurity/cfsec) | cfsec scans CloudFormation configuration files for security issues |
| **cfn_nag** | [https://github.com/stelligent/cfn_nag](https://github.com/stelligent/cfn_nag) |  looks for insecure patterns in CloudFormation |

# Methodologies, whitepapers and architecture

List of resources worth investigating: 
* https://dodcio.defense.gov/Portals/0/Documents/DoD%20Enterprise%20DevSecOps%20Reference%20Design%20v1.0_Public%20Release.pdf
* https://dodcio.defense.gov/Portals/0/Documents/Library/DoDEnterpriseDevSecOpsStrategyGuide.pdf 
* https://csrc.nist.gov/publications/detail/sp/800-204c/draft 
* https://owasp.org/www-project-devsecops-maturity-model/ 
* https://www.sans.org/posters/cloud-security-devsecops-best-practices/ 

AWS DevOps whitepapers: 
* https://d1.awsstatic.com/whitepapers/aws-development-test-environments.pdf
* https://d1.awsstatic.com/whitepapers/AWS_DevOps.pdf
* https://d1.awsstatic.com/whitepapers/AWS_Blue_Green_Deployments.pdf
* https://d1.awsstatic.com/whitepapers/DevOps/import-windows-server-to-amazon-ec2.pdf
* https://d1.awsstatic.com/whitepapers/DevOps/Jenkins_on_AWS.pdf
* https://d1.awsstatic.com/whitepapers/DevOps/practicing-continuous-integration-continuous-delivery-on-AWS.pdf
* https://d1.awsstatic.com/whitepapers/DevOps/infrastructure-as-code.pdf
* https://d1.awsstatic.com/whitepapers/microservices-on-aws.pdf
* https://d1.awsstatic.com/whitepapers/DevOps/running-containerized-microservices-on-aws.pdf

AWS blog: 
* https://aws.amazon.com/blogs/devops/building-end-to-end-aws-devsecops-ci-cd-pipeline-with-open-source-sca-sast-and-dast-tools/

Microsoft whitepapers: 
* https://azure.microsoft.com/mediahandler/files/resourcefiles/6-tips-to-integrate-security-into-your-devops-practices/DevSecOps_Report_Tips_D6_fm.pdf 
* https://docs.microsoft.com/en-us/azure/architecture/solution-ideas/articles/devsecops-in-azure 
* https://docs.microsoft.com/en-us/azure/architecture/solution-ideas/articles/devsecops-in-github 

# Author Profile

![Alt text](IMG/vinoth.JPG?raw=true "VinothKumar")
* <div class="badge-base LI-profile-badge" data-locale="en_US" data-size="medium" data-theme="light" data-type="VERTICAL" data-vanity="pvinothkumar" data-version="v1"><a class="badge-base__link LI-simple-link" href="https://in.linkedin.com/in/pvinothkumar?trk=profile-badge">VinothKumar P</a></div>
              
