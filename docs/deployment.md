# Deployment of the Evaluation Cluster

Any cluster can be used for the evaluation. However, the benchmark was developed primarily using [kind](https://kind.sigs.k8s.io). Thus, `kind` is recommended for local deployments.

The resources can be deployed and removed manually using `kubectl`.
However, for more comfort [Skaffold](https://skaffold.dev) is supported to deploy and delete all the benchmark resources.

## 🐣 Setup

1. Make sure that all manifests have been generated and placed in the `manifests` folder
2. Create a cluster
   - for [kind](https://kind.sigs.k8s.io) the following command can be used:

     ```sh
     kind create cluster --config=cluster.yaml
     ```

3. Ensure that **kubectl context** is set to the target cluster
   - check the current context with:

     ```sh
     kubectl config current-context
     ```

   - the context can be switched with:

     ```sh
     kubectl config use-context <context-name>
     ```

4. Deploy the benchmark resources by running

   ```sh
   skaffold run
   ```

   To avoid waiting for the resources to stabilize add the `--status-check=false` flag.

   💡 _Note: the resources don't have to be in `running` state in order for the tools to analyzes them._

## 💀 Teardown

1. Delete all deployed benchmark resources by running

   ```sh
   skaffold delete
   ```

2. Verify that all the generated resources have been removed by viewing all resources with the `kalm-benchmark` label

   ```sh
   kubectl get all -A -l app.kubernetes.io/part-of=kalm-benchmark
   ```

   💡 _Note: It may take a while until all resources have been deleted - please by patient._

3. Delete the cluster
   - for [kind](https://kind.sigs.k8s.io) is following command can be used:

     ```sh
     kind delete cluster --name kalm-benchmark
     ```

### 🆘 _Help: Resource is stuck in `terminating` state_

Occasionally, it happens that a resource gets stuck in `terminating` state.
If this happens either forcuflly kill the pod/container/resource or delete and re-create the cluster.
See the following links for more details:

- [K8s Issue](https://github.com/kubernetes/kubernetes/issues/25456)
- [StackOverlow: Pods stuck in Terminating status](https://stackoverflow.com/questions/35453792/pods-stuck-in-terminating-status)
- [IBM: A namespace is stuck in the Terminating state](https://www.ibm.com/docs/en/cloud-private/3.1.2?topic=console-namespace-is-stuck-in-terminating-state)
