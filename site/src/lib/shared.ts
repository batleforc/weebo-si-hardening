import { defineSite } from '@weebo/operator-docs/site';

// What makes this site weebo-si-hardening's; everything else comes from
// @weebo/operator-docs. The site carries the generated CRD reference; the
// design (RFCs), the brick pages and the architecture stay plain markdown in
// ../docs, which the pages here link to (RFC 0012, *Documentation site*).
export const site = defineSite({
  name: 'weebo-si-hardening',
  description:
    'Harden the Weebo SI workloads: one operator pinning, fencing and constraining every Eclipse Che workspace, configured by three Kubernetes resources.',
  git: {
    user: 'batleforc',
    repo: 'weebo-si-hardening',
    branch: 'main',
    contentDir: 'site/content/docs',
  },
});
