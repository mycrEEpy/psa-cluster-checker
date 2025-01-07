package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"

	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/pod-security-admission/api"
	"k8s.io/pod-security-admission/policy"
)

var (
	levelStr      = flag.String("level", "baseline", "Pod Security Standards level to check against (baseline, restricted)")
	kubeContext   = flag.String("context", "", "Kubernetes context to use")
	kubeNamespace = flag.String("namespace", "", "Kubernetes namespace to use")
)

func main() {
	flag.Parse()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	level, err := api.ParseLevel(*levelStr)
	if err != nil {
		panic(err)
	}

	cfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		clientcmd.NewDefaultClientConfigLoadingRules(),
		&clientcmd.ConfigOverrides{
			CurrentContext: *kubeContext,
		}).ClientConfig()
	if err != nil {
		panic(err)
	}

	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		panic(err)
	}

	pods, err := client.CoreV1().Pods(*kubeNamespace).List(ctx, meta.ListOptions{})
	if err != nil {
		panic(err)
	}

	evaluator, err := policy.NewEvaluator(policy.DefaultChecks())
	if err != nil {
		panic(err)
	}

	var foundIssue bool

	for _, pod := range pods.Items {
		results := evaluator.EvaluatePod(api.LevelVersion{
			Level:   level,
			Version: api.LatestVersion(),
		}, &pod.ObjectMeta, &pod.Spec)

		for _, result := range results {
			if result.Allowed {
				continue
			}

			foundIssue = true

			fmt.Printf("Pod %s/%s is not allowed to run in %s: %s\n", pod.Namespace, pod.Name, level, result.ForbiddenDetail)
		}
	}

	if foundIssue {
		os.Exit(2)
	}
}
