import { z } from "zod";

export const emailSchema = z
  .string()
  .trim()
  .min(1, "Enter your email address.")
  .max(320, "That email address is too long.")
  .pipe(z.email("Enter a valid email address."));

export const passkeyNameSchema = z.string().trim().max(64, "Use at most 64 characters.");

export const totpCodeSchema = z
  .string()
  .trim()
  .regex(/^\d{6}$/, "Enter the 6-digit code from your authenticator app.");

export const recoveryCodeSchema = z
  .string()
  .trim()
  .min(10, "Enter a recovery code like ABCDE-FGHJK.")
  .max(16, "That doesn't look like a recovery code.");
