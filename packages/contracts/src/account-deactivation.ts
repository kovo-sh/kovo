/** Agent-drafted copy from the #2779 brief, shared by confirmation and notification templates. */
export const ACCOUNT_DEACTIVATION_EMAIL = {
  subject: "Your Kovo account is paused for now",
  message:
    "Hey! We've briefly turned off your Kovo account because we're making some improvements to Kovo. We'd love for you to try it out another time. We'll let you know when it's back on.",
  signature: "— The Kovo team",
} as const;

export const ACCOUNT_REACTIVATION_EMAIL = {
  subject: "Your Kovo account is back on",
  message: "Hey! Your Kovo account is back on. We'd love for you to try it out again.",
  signature: "— The Kovo team",
} as const;
