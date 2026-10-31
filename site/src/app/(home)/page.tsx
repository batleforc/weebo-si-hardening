import { OperatorHome } from '@weebo/operator-docs/site';
import { site } from '@/lib/shared';

export default function HomePage() {
  return (
    <OperatorHome
      site={site}
      label="Kubernetes operator · weebo-si-hardening"
      caption="Pin every Eclipse Che workspace to an admin-authored configuration, fence its network, choose which images it runs and what its processes may do, copy its package-manager configuration and gate its endpoints — per team, switched on one feature and one namespace at a time."
      actions={[
        { href: '/docs/guides/install', label: 'Get started', primary: true },
        { href: '/docs', label: 'Read the docs' },
        { href: '/docs/ide', label: 'Access the CRD IDE' },
      ]}
      install={`kubectl create namespace weebo-si-hardening
kubectl label namespace weebo-si-hardening hardening.weebo.io/exclude=true
helm install weebo-si-operator \\
  oci://ghcr.io/batleforc/charts/weebo-si-operator \\
  -n weebo-si-hardening --set namespace.create=false`}
      example={{
        title: 'dwoc-pin in DryRun',
        yaml: `apiVersion: hardening.weebo.io/v1alpha1
kind: WeeboSiConfig
metadata:
  name: cluster
spec:
  features:
    dwocPin:
      mode: DryRun
      catalog:
        - key: baseline
          name: weebo-hardened-config
          namespace: eclipse-che
      default: baseline`,
      }}
      features={[
        {
          title: 'DryRun runs the real code',
          body: 'Every feature has Off, DryRun and Enforce. DryRun computes exactly what Enforce would and discards it, so a rollout is measured before it is trusted.',
          href: '/docs',
          link: 'Overview',
        },
        {
          title: 'Per team',
          body: 'A WeeboSiTeam selects its namespaces by label and carries its own catalogue and grants for every feature; a WeeboSiUser says who is in it.',
          href: '/docs/crds/weebositeam',
          link: 'WeeboSiTeam',
        },
        {
          title: 'On the weebo kit',
          body: 'Same telemetry, probes, leader election, Events and webhook server as every weebo operator.',
          href: '/docs/guides/observability',
          link: 'Observability',
        },
      ]}
    />
  );
}
