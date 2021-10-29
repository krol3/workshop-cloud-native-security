# Policies with OPA

```
trivy conf --severity CRITICAL .
```

Customize Rules in Containers

```
trivy conf --severity CRITICAL --policy ./policy/container --namespaces mycontainer .
```

Customize Rules in Kubernetes

```
trivy conf --severity CRITICAL --policy ./policy/k8s --namespaces myk8s .
```

> More samples about Customization with OPA [here](https://github.com/aquasecurity/trivy/tree/main/examples/misconf)
