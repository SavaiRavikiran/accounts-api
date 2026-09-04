# Egress control — accounts-api → KYC provider

**Layer implemented:** two layers, deliberately not one.

1. **L3/L4 — `NetworkPolicy`** ([networkpolicy-l3.yaml](networkpolicy-l3.yaml)):
   default-deny egress except DNS and HTTPS to non-RFC1918 destinations. This
   works on any CNI and ships day one. It cannot express "only the KYC
   provider" — it can only express "not inside our own VPC" — because
   Kubernetes `NetworkPolicy` has no hostname/SNI awareness.
2. **L7 — `CiliumNetworkPolicy` with `toFQDNs`** ([ciliumnetworkpolicy-l7.yaml](ciliumnetworkpolicy-l7.yaml)):
   names the KYC provider's hostname explicitly. **Assumption stated up front:**
   this requires Cilium as the cluster CNI. I don't know what CNI the shared
   EKS cluster actually runs, so I've committed both layers — if the CNI
   doesn't support `toFQDNs` (e.g. stock VPC CNI), the equivalent control is a
   forward proxy (e.g. Squid/Envoy egress gateway) with a domain allow-list
   and TLS SNI inspection, or an explicit static IP allow-list from the KYC
   provider if they publish one (most third-party APIs behind a CDN don't,
   which is precisely why FQDN or proxy-based control beats IP allow-listing
   here).

## What this still fails to stop

- **DNS rebinding / IP reuse**: `toFQDNs` resolves the name to IPs and allows
  those IPs; a provider whose IPs rotate faster than Cilium's DNS cache
  TTL handling can create a brief window of stale allow. Low risk for a
  KYC vendor with stable infrastructure, but it is a real gap, not a
  theoretical one.
- **Data exfiltration *to* the KYC provider itself**: this control only
  restricts *destination*, not *content*. A compromised `accounts-api`
  process can still send arbitrary data to the KYC provider's hostname over
  the legitimate, allowed channel (e.g. stuff extra customer records into a
  KYC-check request body). Egress allow-listing defends against "call out
  anywhere"; it does not defend against "abuse the one channel you're allowed."
  That residual risk is accepted here and would need application-layer output
  validation or DLP to close — out of scope for this control.
- **Compromised KYC provider**: if the third party itself is compromised, this
  control does nothing — it authenticates the destination, not the destination's
  trustworthiness. TLS + response validation in the app is the actual mitigation
  for that threat, not egress policy.
- **East-west inside the allowed CIDR**: the L3 policy's "not RFC1918" rule is
  a blunt instrument; it still allows the pod to reach *any* other non-private
  destination on 443, not only the KYC provider, until the L7 policy is in
  place (or the CNI substitute above is). This is why the L3 policy alone is
  not the final control — it's the fallback for clusters where L7 FQDN
  filtering isn't available.
