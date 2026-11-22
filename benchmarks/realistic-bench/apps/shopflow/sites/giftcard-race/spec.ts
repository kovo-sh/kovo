import type { SiteSpec } from '../../../../lib/types.ts'

export const spec: SiteSpec = {
  id: 'giftcard-race',
  title: 'Gift-card redemption double spend',
  vulnClass: 'race_condition',
  cwe: 'CWE-362',
  severity: 'high',
  routeKeys: ['redeemGiftCard'],
  params: ['giftCardId', 'bodyAmount'],
  oracle: { kinds: ['race_double_spend'], routeKeys: ['redeemGiftCard'] },
  rootCause: { file: 'billing/giftcards.ts', symbol: 'redeemGiftCard' },
  formEncoding: 'json',
  lure: 'reads the balance and writes it back with a check-then-act gap under load',
}
