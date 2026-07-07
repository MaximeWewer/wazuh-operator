package deployments

import (
	"testing"

	appsv1 "k8s.io/api/apps/v1"
)

// TestSharedConfigMapContent asserts that both the master and worker builders render the
// shared ConfigMap-backed volumes and mounts (rules, decoders, agent-group files,
// integrations, CDB lists, active responses) through the shared base helpers. It guards
// against the shared configMapVolumes/configMapMounts wiring regressing in one builder.
func TestSharedConfigMapContent(t *testing.T) {
	rules := []RuleConfigMapRef{{Name: "cm-rule", FileName: "r.xml"}}
	decoders := []DecoderConfigMapRef{{Name: "cm-dec", FileName: "d.xml"}}
	cdb := []CDBListConfigMapRef{{Name: "cm-cdb", FileName: "ioc/ip", Key: "ip"}}
	ar := []ActiveResponseConfigMapRef{{Name: "cm-ar", FileName: "fw.sh"}}
	integ := []IntegrationConfigMapRef{{Name: "cm-int", FileName: "custom-x"}}
	groups := []AgentGroupFileRef{{ConfigMapName: "cm-g", GroupName: "g1", FileNames: []string{"agent.conf"}}}

	// volume name -> expected mount path, produced by the shared helpers.
	want := map[string]string{
		"wazuh-rule-cm-rule":         "/var/ossec/etc/rules/r.xml",
		"wazuh-decoder-cm-dec":       "/var/ossec/etc/decoders/d.xml",
		"agentgroup-files-cm-g":      "/var/ossec/etc/shared/g1/agent.conf",
		"wazuh-integration-cm-int":   "/var/ossec/integrations/custom-x",
		"wazuh-cdblist-cm-cdb":       "/var/ossec/etc/lists/ioc/ip",
		"wazuh-activeresponse-cm-ar": "/var/ossec/active-response/bin/fw.sh",
	}

	master := NewManagerStatefulSetBuilder("cluster", "ns", "master").
		WithRuleConfigMaps(rules).WithDecoderConfigMaps(decoders).WithCDBListConfigMaps(cdb).
		WithActiveResponseConfigMaps(ar).WithIntegrationConfigMaps(integ).WithAgentGroupFiles(groups).
		Build()
	worker := NewWorkerStatefulSetBuilder("cluster", "ns").
		WithRuleConfigMaps(rules).WithDecoderConfigMaps(decoders).WithCDBListConfigMaps(cdb).
		WithActiveResponseConfigMaps(ar).WithIntegrationConfigMaps(integ).WithAgentGroupFiles(groups).
		Build()

	for _, tc := range []struct {
		name string
		sts  *appsv1.StatefulSet
	}{{"master", master}, {"worker", worker}} {
		vols := map[string]bool{}
		for _, v := range tc.sts.Spec.Template.Spec.Volumes {
			vols[v.Name] = true
		}
		mnts := map[string]string{}
		for _, m := range tc.sts.Spec.Template.Spec.Containers[0].VolumeMounts {
			mnts[m.Name] = m.MountPath
		}
		for name, path := range want {
			if !vols[name] {
				t.Errorf("%s: missing volume %q", tc.name, name)
			}
			if got := mnts[name]; got != path {
				t.Errorf("%s: mount %q at %q, want %q", tc.name, name, got, path)
			}
		}
	}
}
