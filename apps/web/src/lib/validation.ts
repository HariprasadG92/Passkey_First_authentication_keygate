import { z } from "zod";

export const emailSchema = z
  .string()
  .trim()
  .min(1, "Enter your email address.")
  .max(320, "That email address is too long.")
  .pipe(z.email("Enter a valid email address."));

export const passkeyNameSchema = z.string().trim().max(64, "Use at most 64 characters.");
