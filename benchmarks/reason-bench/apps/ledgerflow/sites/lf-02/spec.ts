import type { SiteSpec } from '../../../../lib/types.ts'

export const spec: SiteSpec = {
  id: 'lf-02',
  title: 'Multi-currency conversion rounds in the holder favour in one direction only',
  vulnClass: 'business_logic',
  cwe: 'CWE-840',
  severity: 'high',
  family: 'A',
  routeKeys: ['convertWallet'],
  params: ['walletId', 'amount'],
  oracle: { kinds: ['economic_invariant_violation'], routeKeys: ['convertWallet'] },
  rootCause: { file: 'wallet/currency-quote.ts', symbol: 'register' },
  lure: 'quotes both directions from the stored per-wallet rates and returns a readable conversion breakdown',
  canBeDecoy: true,
}
