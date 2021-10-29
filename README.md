# Security Cloud-Native Workshop

Security across Development life cycle in Cloud-Native

[![SDLC](https://holisticsecurity.io/assets/blog20200210/20200210-security-along-container-based-sdlc-v2.png)](https://holisticsecurity.io/2020/02/10/security-along-the-sdlc-for-cloud-native-apps/)

</br>

# Quick Start Workshop (2-hours)


In this quick start hands-on workshop, you will explore the build, infrastructure and runtime in Cloud-Native.

[![secure-container](https://www.redhat.com/outfit/3c814deb579d4de95d1eb7207aa9f2e4/cl-cloud-native-container-design-whitepaper_Image6_v2.png)](https://www.redhat.com/en/resources/cloud-native-container-design-whitepaper)

How could you embed security across all stages of Software Development Life Cycle?. Build, infra, and runtime will be the key points of this workshop. We will explore good practices to embed security along the container images, Kubernetes, infrastructure as a code, and workloads and how to DevOps practices will help its adoption together with tools to implement security, compliance, and forensic.


## Table of Contents
- [Prerequisites](#prerequisites)
- [Container Threads](https://github.com/krol3/container-security-checklist#container-threat-model)
- [Container Security Best Practices](https://github.com/krol3/container-security-checklist#container-security-checklist)
- [Detecting Vulnerabilities](vulnerabilities.md)
    - Container images
    - Filesystems
    - Git repositories
    - Application dependencies by Language
    - CI Integration: Github Action
- [Detecting Misconfigurations](misconfigurations.md)
    - Container Images
    - Kubernetes
    - Infra as a Code: Terraform
    - CI Integration: Github Action
- [Security Audit in Kubernetes](audit-k8s.md)
    - Workloads Scanning
    - Kubernetes CIS Benchmark
    - Kubernetes Pentesting: kube-hunter
    - Audit Reports
      - Polaris
      - Conftest
    - Integration
      - Lens
      - Octant
- [Policy as Code with OPA](opa.md)
    - Vulnerabilities
    - container image
    - Kubernetes
- [Runtime Detection in Containers](runtime.md)
    - Container
    - Kubernetes installation
    - Alerting
- [Collaborate](#collaborate)

## Prerequisites

Before you begin, you need the following software:

- A Linux, stand-alone virtual machine (VM)
- A kubernetes cluster: minikube, kind, or any kubernetes flavor.
    - **Minikube Installation** [here](https://minikube.sigs.k8s.io/docs/start/)
    - **Kind Installation** [here](https://kind.sigs.k8s.io/docs/user/quick-start/#installation)
- Kubernetes command-line tool: **kubectl** Installation on Linux [here](https://kubernetes.io/docs/tasks/tools/install-kubectl-linux/)

Note: For Infrastructure scanning, it will be used a kind cluster with two nodes. See the [kind.yaml](kind.yaml)

`kind create cluster --name k8s-local --config kind.yaml --image kindest/node:v1.20.7`

## Congratulations

Thank you for attending the workshop. I would love your feedback, or contribution for other cases and samples with other scenaries.

## Collaborate

If you find any typos, errors, outdated resources; or if you have a different point of view. Please open a pull request or contact me.

Pull requests and stars are always welcome 🙌
