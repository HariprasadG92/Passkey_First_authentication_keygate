import {
  startAuthentication,
  startRegistration,
  WebAuthnError,
  type PublicKeyCredentialCreationOptionsJSON,
  type PublicKeyCredentialRequestOptionsJSON,
} from "@simplewebauthn/browser";
import { api, ApiError, type SessionInfo } from "@/lib/api";

/** Turn browser WebAuthn errors into something a person can act on. */
export function describePasskeyError(err: unknown): string {
  if (err instanceof ApiError) return err.message;
  const name =
    err instanceof WebAuthnError ? err.cause && (err.cause as Error).name : (err as Error)?.name;
  switch (name) {
    case "NotAllowedError":
      return "The passkey prompt was cancelled or timed out.";
    case "InvalidStateError":
      return "This authenticator is already registered to your account.";
    case "SecurityError":
      return "This page's address isn't allowed to use passkeys for Keygate.";
    case "NotSupportedError":
      return "This browser or device doesn't support passkeys.";
    default:
      return "Something went wrong with the passkey. Please try again.";
  }
}

export async function registerFirstPasskey(friendlyName: string): Promise<SessionInfo> {
  const optionsJSON = await api<PublicKeyCredentialCreationOptionsJSON>(
    "/auth/passkeys/register/options",
    { method: "POST" },
  );
  const credential = await startRegistration({ optionsJSON });
  return api<SessionInfo>("/auth/passkeys/register/verify", {
    method: "POST",
    body: { credential, friendly_name: friendlyName || null },
  });
}

export async function signInWithPasskey(email?: string): Promise<SessionInfo> {
  const { ceremony_id, options } = await api<{
    ceremony_id: string;
    options: PublicKeyCredentialRequestOptionsJSON;
  }>("/auth/passkeys/login/options", { method: "POST", body: email ? { email } : {} });
  const credential = await startAuthentication({ optionsJSON: options });
  return api<SessionInfo>("/auth/passkeys/login/verify", {
    method: "POST",
    body: { ceremony_id, credential },
  });
}

export async function addPasskey(friendlyName: string): Promise<void> {
  const optionsJSON = await api<PublicKeyCredentialCreationOptionsJSON>(
    "/account/passkeys/register/options",
    { method: "POST" },
  );
  const credential = await startRegistration({ optionsJSON });
  await api("/account/passkeys/register/verify", {
    method: "POST",
    body: { credential, friendly_name: friendlyName || null },
  });
}

export async function stepUpWithPasskey(): Promise<void> {
  const optionsJSON = await api<PublicKeyCredentialRequestOptionsJSON>(
    "/auth/step-up/passkey/options",
    { method: "POST" },
  );
  const credential = await startAuthentication({ optionsJSON });
  await api("/auth/step-up/passkey/verify", { method: "POST", body: { credential } });
}
