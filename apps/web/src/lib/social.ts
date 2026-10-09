import { api } from "@/lib/api";

export type SocialProvider = { id: "github" | "google"; name: string };
export type SocialIntent = "signin" | "link" | "stepup";

export function listProviders(): Promise<SocialProvider[]> {
  return api<SocialProvider[]>("/auth/social/providers");
}

/** Ask the API to start a flow (sets the browser-binding cookie), then go to the provider. */
export async function startSocial(provider: string, intent: SocialIntent): Promise<void> {
  const { authorize_url } = await api<{ authorize_url: string }>(`/auth/social/${provider}/start`, {
    method: "POST",
    body: { intent },
  });
  window.location.assign(authorize_url);
}

export const SOCIAL_ERRORS: Record<string, string> = {
  social_failed: "Sign-in with that provider didn't complete. Please try again.",
  social_unverified_email:
    "That provider account has no verified email address. Verify it with the provider, or sign up with email instead.",
  social_email_in_use:
    "A Keygate account already uses that email. Sign in with your passkey, then link this provider from your account page.",
  unverified_email: "That provider account has no verified email address, so it can't be linked.",
  linked_elsewhere: "That provider account is already linked to a different Keygate account.",
  already_linked: "That provider account is already linked to your account.",
  stepup_failed:
    "Confirmation failed: use a provider account that's linked to this Keygate account.",
};
