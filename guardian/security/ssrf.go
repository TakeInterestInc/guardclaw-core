// Copyright 2025-2026 TakeInterest Inc.
// SPDX-License-Identifier: Apache-2.0

// Package security provides SSRF (Server-Side Request Forgery) detection for AI agents
// that make HTTP requests on behalf of users.
package security

import (
	"regexp"
	"strings"
)

// SSRFCategory categorizes SSRF attack types.
type SSRFCategory string

const (
	SSRFCategoryCloudMetadata   SSRFCategory = "cloud_metadata"
	SSRFCategoryInternalIP      SSRFCategory = "internal_ip"
	SSRFCategoryDNSRebinding    SSRFCategory = "dns_rebinding"
	SSRFCategoryProtocolSmuggle SSRFCategory = "protocol_smuggle"
	SSRFCategoryURLBypass       SSRFCategory = "url_bypass"
	SSRFCategoryInternalService SSRFCategory = "internal_service"
	SSRFCategoryKubernetes      SSRFCategory = "kubernetes"
	SSRFCategoryDocker          SSRFCategory = "docker_container"
	SSRFCategoryAzure           SSRFCategory = "azure_cloud"
	SSRFCategoryOtherCloud      SSRFCategory = "other_cloud"
	SSRFCategoryProtocolURI     SSRFCategory = "protocol_uri"
)

// SSRFPattern represents an SSRF detection pattern.
type SSRFPattern struct {
	Pattern    *regexp.Regexp
	Category   SSRFCategory
	Severity   float64 // 0.0-1.0
	Confidence float64 // 0.0-1.0
	Name       string
	Example    string
}

// SSRFPatterns contains comprehensive SSRF detection patterns.
// Total: 40 patterns across 6 categories.
var SSRFPatterns = []SSRFPattern{
	// === Cloud Metadata Endpoints (10 patterns) ===
	{regexp.MustCompile(`(?i)169\.254\.169\.254`), SSRFCategoryCloudMetadata, 0.95, 0.95, "aws_metadata_ip", `http://169.254.169.254/latest/meta-data/`},
	{regexp.MustCompile(`(?i)metadata\.google\.internal`), SSRFCategoryCloudMetadata, 0.95, 0.95, "gcp_metadata_host", `http://metadata.google.internal/computeMetadata/v1/`},
	{regexp.MustCompile(`(?i)100\.100\.100\.200`), SSRFCategoryCloudMetadata, 0.90, 0.90, "alibaba_metadata_ip", `http://100.100.100.200/latest/meta-data/`},
	{regexp.MustCompile(`(?i)169\.254\.170\.2`), SSRFCategoryCloudMetadata, 0.90, 0.90, "aws_ecs_metadata", `http://169.254.170.2/v2/credentials/`},
	{regexp.MustCompile(`(?i)/latest/meta-data/`), SSRFCategoryCloudMetadata, 0.85, 0.80, "metadata_path_aws", `http://example.com/latest/meta-data/iam/security-credentials/`},
	{regexp.MustCompile(`(?i)/computeMetadata/v1/`), SSRFCategoryCloudMetadata, 0.90, 0.90, "metadata_path_gcp", `http://example.com/computeMetadata/v1/instance/service-accounts/`},
	{regexp.MustCompile(`(?i)/metadata/v1/`), SSRFCategoryCloudMetadata, 0.85, 0.80, "metadata_path_do", `http://169.254.169.254/metadata/v1/`},
	{regexp.MustCompile(`(?i)Metadata-Flavor:\s*Google`), SSRFCategoryCloudMetadata, 0.90, 0.90, "gcp_metadata_header", `Metadata-Flavor: Google`},
	{regexp.MustCompile(`(?i)169\.254\.169\.254.*?(?:iam|credentials|token|api-key|secret)`), SSRFCategoryCloudMetadata, 0.95, 0.95, "metadata_credential_theft", `http://169.254.169.254/latest/meta-data/iam/security-credentials/role-name`},
	{regexp.MustCompile(`(?i)/instance/service-accounts/`), SSRFCategoryCloudMetadata, 0.90, 0.90, "gcp_sa_token", `http://metadata/computeMetadata/v1/instance/service-accounts/default/token`},

	// === Internal IP Ranges (8 patterns) ===
	{regexp.MustCompile(`(?i)(?:https?://)?(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3})`), SSRFCategoryInternalIP, 0.80, 0.75, "rfc1918_class_a", `http://10.0.0.1/admin`},
	{regexp.MustCompile(`(?i)(?:https?://)?172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}`), SSRFCategoryInternalIP, 0.80, 0.75, "rfc1918_class_b", `http://172.16.0.1/`},
	{regexp.MustCompile(`(?i)(?:https?://)?192\.168\.\d{1,3}\.\d{1,3}`), SSRFCategoryInternalIP, 0.80, 0.75, "rfc1918_class_c", `http://192.168.1.1/`},
	{regexp.MustCompile(`(?i)(?:https?://)?127\.\d{1,3}\.\d{1,3}\.\d{1,3}`), SSRFCategoryInternalIP, 0.90, 0.85, "loopback_ip", `http://127.0.0.1:8080/`},
	{regexp.MustCompile(`(?i)(?:https?://)?0\.0\.0\.0`), SSRFCategoryInternalIP, 0.90, 0.85, "all_interfaces_ip", `http://0.0.0.0:8080/`},
	{regexp.MustCompile(`(?i)https?://localhost(?::\d+)?/(?:admin|internal|actuator|metadata|metrics|debug|\.env|api/internal)`), SSRFCategoryInternalIP, 0.85, 0.85, "localhost_hostname", `http://localhost:3000/admin`},
	{regexp.MustCompile(`(?i)(?:https?://)\[::1?\]`), SSRFCategoryInternalIP, 0.90, 0.85, "ipv6_loopback", `http://[::1]/`},
	{regexp.MustCompile(`(?i)(?:https?://)\[(?:fc|fd)[0-9a-f]{2}:`), SSRFCategoryInternalIP, 0.80, 0.75, "ipv6_private", `http://[fc00::1]/`},

	// === DNS Rebinding / Hostname Tricks (6 patterns) ===
	{regexp.MustCompile(`(?i)(?:https?://)?(?:\d+\.){3}\d+\.(?:nip\.io|xip\.io|sslip\.io)\b`), SSRFCategoryDNSRebinding, 0.90, 0.90, "wildcard_dns_service", `http://169.254.169.254.nip.io/`},
	{regexp.MustCompile(`(?i)(?:https?://)?0x[0-9a-f]+(?:\.|$)`), SSRFCategoryDNSRebinding, 0.85, 0.80, "hex_ip_encoding", `http://0x7f000001/`},
	{regexp.MustCompile(`(?i)https?://\d{8,10}(?:[:/]|$)`), SSRFCategoryDNSRebinding, 0.85, 0.80, "decimal_ip_encoding", `http://2130706433/`},
	{regexp.MustCompile(`(?i)(?:https?://)?0177\.0+\.0+\.0*1\b`), SSRFCategoryDNSRebinding, 0.90, 0.85, "octal_ip_encoding", `http://0177.0.0.01/`},
	{regexp.MustCompile(`(?i)(?:https?://)?[^/]*@[^/]*169\.254`), SSRFCategoryDNSRebinding, 0.90, 0.90, "userinfo_bypass", `http://evil@169.254.169.254/`},
	{regexp.MustCompile(`(?i)(?:https?://)?[^/]*#[^/]*169\.254`), SSRFCategoryDNSRebinding, 0.85, 0.85, "fragment_bypass", `http://evil.com#169.254.169.254`},

	// === Protocol Smuggling (5 patterns) ===
	{regexp.MustCompile(`(?i)gopher://`), SSRFCategoryProtocolSmuggle, 0.95, 0.90, "gopher_protocol", `gopher://127.0.0.1:25/_HELO`},
	{regexp.MustCompile(`(?i)dict://`), SSRFCategoryProtocolSmuggle, 0.90, 0.85, "dict_protocol", `dict://127.0.0.1:6379/INFO`},
	{regexp.MustCompile(`(?i)file:///(?:etc/|root/|proc/|sys/|var/|home/[^/]+/\.(?:ssh|aws|config)|[^/]*\.(?:env|pem|key))`), SSRFCategoryProtocolSmuggle, 0.90, 0.85, "file_protocol", `file:///etc/passwd`},
	{regexp.MustCompile(`(?i)ldap://`), SSRFCategoryProtocolSmuggle, 0.85, 0.80, "ldap_protocol", `ldap://127.0.0.1/`},
	{regexp.MustCompile(`(?i)tftp://`), SSRFCategoryProtocolSmuggle, 0.85, 0.80, "tftp_protocol", `tftp://evil.com/payload`},

	// === URL Bypass Techniques (5 patterns) ===
	{regexp.MustCompile(`(?i)(?:https?://)[^/]*\\[^/]`), SSRFCategoryURLBypass, 0.85, 0.80, "backslash_url_bypass", `http://evil.com\@169.254.169.254/`},
	{regexp.MustCompile(`(?i)(?:https?://)(?:\d{1,3}\.){3}\d{1,3}[\s\x00]`), SSRFCategoryURLBypass, 0.85, 0.80, "null_terminated_ip", "http://127.0.0.1\x00.evil.com/"},
	{regexp.MustCompile(`(?i)(?:https?://).*?\.burpcollaborator\.net`), SSRFCategoryURLBypass, 0.85, 0.85, "burp_collaborator", `http://foo.burpcollaborator.net/`},
	{regexp.MustCompile(`(?i)(?:https?://).*?\.oastify\.com`), SSRFCategoryURLBypass, 0.85, 0.85, "oast_domain", `http://foo.oastify.com/`},
	{regexp.MustCompile(`(?i)(?:https?://).*?\.interact\.sh`), SSRFCategoryURLBypass, 0.85, 0.85, "interactsh_domain", `http://foo.interact.sh/`},

	// === Internal Service Probing (6 patterns) ===
	{regexp.MustCompile(`(?i)(?:https?://)[^/]*:(?:6379|11211|27017|5432|3306|9200)\b`), SSRFCategoryInternalService, 0.90, 0.85, "database_port_probe", `http://127.0.0.1:6379/`},
	{regexp.MustCompile(`(?i)(?:https?://)[^/]*:(?:2375|2376)\b`), SSRFCategoryInternalService, 0.95, 0.90, "docker_api_probe", `http://127.0.0.1:2375/containers/json`},
	{regexp.MustCompile(`(?i)(?:https?://)[^/]*:(?:8500|8600)\b`), SSRFCategoryInternalService, 0.85, 0.80, "consul_probe", `http://127.0.0.1:8500/v1/agent/self`},
	{regexp.MustCompile(`(?i)(?:https?://)[^/]*:(?:2379|2380)\b`), SSRFCategoryInternalService, 0.90, 0.85, "etcd_probe", `http://127.0.0.1:2379/v2/keys/`},
	{regexp.MustCompile(`(?i)(?:https?://)[^/]*:(?:10250|10255)\b`), SSRFCategoryInternalService, 0.95, 0.90, "kubelet_probe", `http://127.0.0.1:10250/pods`},
	{regexp.MustCompile(`(?i)(?:https?://)[^/]*:(?:9090|9093)\b.*?/(?:api|targets|alerts)`), SSRFCategoryInternalService, 0.85, 0.80, "prometheus_probe", `http://127.0.0.1:9090/api/v1/targets`},

	// === Kubernetes (12 patterns) ===
	{regexp.MustCompile(`(?i)\.svc\.cluster\.local\b`), SSRFCategoryKubernetes, 0.95, 0.90, "k8s_svc_cluster_local", `http://service.namespace.svc.cluster.local/`},
	{regexp.MustCompile(`(?i)kubernetes\.default\.svc\b`), SSRFCategoryKubernetes, 0.95, 0.95, "k8s_default_svc", `http://kubernetes.default.svc/`},
	{regexp.MustCompile(`(?i)/var/run/secrets/kubernetes\.io/`), SSRFCategoryKubernetes, 1.0, 0.95, "k8s_sa_token", `/var/run/secrets/kubernetes.io/serviceaccount/token`},
	{regexp.MustCompile(`(?i):10250/(?:pods|exec|run|attach|portForward)\b`), SSRFCategoryKubernetes, 1.0, 0.95, "kubelet_api_verb", `http://node:10250/pods`},
	{regexp.MustCompile(`(?i):10255/(?:pods|metrics|spec)\b`), SSRFCategoryKubernetes, 0.90, 0.85, "kubelet_readonly", `http://node:10255/pods`},
	{regexp.MustCompile(`(?i):10249/`), SSRFCategoryKubernetes, 0.85, 0.80, "kube_proxy_metrics", `http://node:10249/metrics`},
	{regexp.MustCompile(`(?i):(?:6443|8443)/api(?:/v1)?\b`), SSRFCategoryKubernetes, 0.95, 0.90, "k8s_api_server", `https://master:6443/api/v1`},
	{regexp.MustCompile(`(?i)/api/v1/namespaces/`), SSRFCategoryKubernetes, 0.90, 0.85, "k8s_namespaces_api", `/api/v1/namespaces/kube-system/secrets`},
	{regexp.MustCompile(`(?i)/apis/(?:apps|batch|extensions)/v\d`), SSRFCategoryKubernetes, 0.85, 0.80, "k8s_group_api", `/apis/apps/v1/deployments`},
	{regexp.MustCompile(`(?i)kube-system`), SSRFCategoryKubernetes, 0.75, 0.70, "k8s_kube_system_ref", `namespace=kube-system`},
	{regexp.MustCompile(`(?i)/api/v1/nodes\b`), SSRFCategoryKubernetes, 0.85, 0.85, "k8s_nodes_api", `/api/v1/nodes`},
	{regexp.MustCompile(`(?i)/healthz`), SSRFCategoryKubernetes, 0.70, 0.65, "k8s_healthz", `/healthz`},

	// === Docker/Container (8 patterns) ===
	{regexp.MustCompile(`(?i)unix:///var/run/docker\.sock`), SSRFCategoryDocker, 1.0, 0.98, "docker_sock_unix", `unix:///var/run/docker.sock`},
	{regexp.MustCompile(`(?i)unix:///run/podman/podman\.sock`), SSRFCategoryDocker, 1.0, 0.95, "podman_sock_unix", `unix:///run/podman/podman.sock`},
	{regexp.MustCompile(`(?i)\bhost\.docker\.internal\b`), SSRFCategoryDocker, 0.90, 0.85, "docker_host_internal", `http://host.docker.internal/`},
	{regexp.MustCompile(`(?i)\bgateway\.docker\.internal\b`), SSRFCategoryDocker, 0.85, 0.80, "docker_gateway_internal", `http://gateway.docker.internal/`},
	{regexp.MustCompile(`(?i):2377\b`), SSRFCategoryDocker, 0.85, 0.80, "docker_swarm_port", `http://manager:2377/`},
	{regexp.MustCompile(`(?i)/containers/json\b`), SSRFCategoryDocker, 0.95, 0.90, "docker_containers_json", `/containers/json`},
	{regexp.MustCompile(`(?i)/images/json\b`), SSRFCategoryDocker, 0.90, 0.85, "docker_images_json", `/images/json`},
	{regexp.MustCompile(`(?i)/volumes\b`), SSRFCategoryDocker, 0.80, 0.75, "docker_volumes_api", `/volumes`},

	// === Azure Cloud (8 patterns) ===
	{regexp.MustCompile(`(?i)169\.254\.169\.254.*api-version=`), SSRFCategoryAzure, 0.95, 0.95, "azure_imds_api_version", `http://169.254.169.254/metadata/instance?api-version=2021-02-01`},
	{regexp.MustCompile(`(?i)/metadata/instance\b`), SSRFCategoryAzure, 0.90, 0.85, "azure_metadata_instance", `/metadata/instance`},
	{regexp.MustCompile(`(?i)/metadata/identity/oauth2/token`), SSRFCategoryAzure, 0.95, 0.90, "azure_identity_token", `/metadata/identity/oauth2/token`},
	{regexp.MustCompile(`(?i)\.vault\.azure\.net\b`), SSRFCategoryAzure, 0.90, 0.85, "azure_keyvault", `https://myvault.vault.azure.net/`},
	{regexp.MustCompile(`(?i)\.blob\.core\.windows\.net\b`), SSRFCategoryAzure, 0.80, 0.75, "azure_blob_storage", `https://account.blob.core.windows.net/`},
	{regexp.MustCompile(`(?i)\.database\.windows\.net\b`), SSRFCategoryAzure, 0.85, 0.80, "azure_sql", `server.database.windows.net`},
	{regexp.MustCompile(`(?i)management\.azure\.com\b`), SSRFCategoryAzure, 0.90, 0.85, "azure_management_api", `https://management.azure.com/`},
	{regexp.MustCompile(`(?i)\.azurewebsites\.net\b`), SSRFCategoryAzure, 0.75, 0.70, "azure_webapp", `https://app.azurewebsites.net/`},

	// === Other Cloud Providers (8 patterns) ===
	{regexp.MustCompile(`(?i)169\.254\.16\.11\b`), SSRFCategoryOtherCloud, 0.90, 0.90, "tencent_metadata_ip", `http://169.254.16.11/latest/meta-data/`},
	{regexp.MustCompile(`(?i)/opc/v[12]/`), SSRFCategoryOtherCloud, 0.90, 0.85, "oracle_metadata", `http://169.254.169.254/opc/v1/instance/`},
	{regexp.MustCompile(`(?i)100\.115\.92\.\d`), SSRFCategoryOtherCloud, 0.85, 0.80, "gcp_special_range", `http://100.115.92.1/`},
	{regexp.MustCompile(`(?i)fd00:ec2::254\b`), SSRFCategoryOtherCloud, 0.90, 0.90, "aws_ipv6_metadata", `http://[fd00:ec2::254]/latest/`},
	{regexp.MustCompile(`(?i)/userData\b`), SSRFCategoryOtherCloud, 0.80, 0.75, "cloud_userdata", `http://169.254.169.254/latest/userData`},
	{regexp.MustCompile(`(?i)169\.254\.0\.1\b`), SSRFCategoryOtherCloud, 0.85, 0.80, "hetzner_metadata_ip", `http://169.254.0.1/`},
	{regexp.MustCompile(`(?i)169\.254\.\d+\.\d+.*?/(?:token|identity|credentials)\b`), SSRFCategoryOtherCloud, 0.90, 0.90, "link_local_cred_steal", `http://169.254.x.x/token`},
	{regexp.MustCompile(`(?i)instance-data/latest\b`), SSRFCategoryOtherCloud, 0.85, 0.80, "scaleway_metadata", `http://169.254.42.42/instance-data/latest`},

	// === Protocol URIs (9 patterns) ===
	{regexp.MustCompile(`(?i)redis://`), SSRFCategoryProtocolURI, 0.90, 0.85, "redis_uri", `redis://127.0.0.1:6379/`},
	{regexp.MustCompile(`(?i)mongodb(?:\+srv)?://`), SSRFCategoryProtocolURI, 0.85, 0.80, "mongodb_uri", `mongodb://127.0.0.1:27017/`},
	{regexp.MustCompile(`(?i)postgres(?:ql)?://[^/\s:]+:[^/\s@]+@`), SSRFCategoryProtocolURI, 0.85, 0.80, "postgres_uri", `postgres://user:pass@host/db`},
	{regexp.MustCompile(`(?i)mysql://`), SSRFCategoryProtocolURI, 0.85, 0.80, "mysql_uri", `mysql://user:pass@host/db`},
	{regexp.MustCompile(`(?i)memcached://`), SSRFCategoryProtocolURI, 0.85, 0.80, "memcached_uri", `memcached://127.0.0.1:11211/`},
	{regexp.MustCompile(`(?i)amqp://`), SSRFCategoryProtocolURI, 0.80, 0.75, "amqp_uri", `amqp://guest:guest@host/`},
	{regexp.MustCompile(`(?i)mqtt://`), SSRFCategoryProtocolURI, 0.80, 0.75, "mqtt_uri", `mqtt://broker.example.com/`},
	{regexp.MustCompile(`(?i)rtsp://`), SSRFCategoryProtocolURI, 0.80, 0.75, "rtsp_uri", `rtsp://camera.internal/stream`},
	{regexp.MustCompile(`(?i)rsync://`), SSRFCategoryProtocolURI, 0.80, 0.75, "rsync_uri", `rsync://host/module`},
}

// CheckSSRF checks input for SSRF patterns and returns all findings.
func CheckSSRF(input string) []SSRFFinding {
	if len(input) == 0 {
		return nil
	}

	var findings []SSRFFinding

	// Quick pre-filter: skip if no URL-like or IP-like content
	if !strings.ContainsAny(input, ":/0123456789") {
		return nil
	}

	for i := range SSRFPatterns {
		p := &SSRFPatterns[i]
		if p.Pattern.MatchString(input) {
			findings = append(findings, SSRFFinding{
				Pattern:    p,
				MatchedStr: p.Pattern.FindString(input),
			})
		}
	}
	return findings
}

// SSRFFinding represents a matched SSRF pattern.
type SSRFFinding struct {
	Pattern    *SSRFPattern
	MatchedStr string
}
