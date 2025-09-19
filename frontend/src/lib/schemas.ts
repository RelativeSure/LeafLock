import { z } from 'zod'

export const adminUserSchema = z.object({
  user_id: z.string().min(1, 'user_id is required'),
  email: z.string().email('invalid email address'),
  is_admin: z.boolean(),
  admin_via_allowlist: z.boolean().optional(),
  mfa_enabled: z.boolean().optional().default(false),
  roles: z.array(z.string()),
  created_at: z.string().optional(),
  last_login: z.string().nullable().optional(),
  registration_ip: z.string().optional(),
  last_ip: z.string().optional(),
})

export const adminListUsersResponseSchema = z.object({
  users: z.array(adminUserSchema),
  total: z.coerce.number().int().nonnegative(),
})

export const registrationStatusSchema = z.object({
  enabled: z.boolean(),
})

export const adminUserRolesResponseSchema = z.object({
  roles: z.array(z.string()),
})

export const adminActionResponseSchema = z
  .object({
    ok: z.boolean().optional(),
    affected: z.number().int().nonnegative().optional(),
    processed: z.number().int().nonnegative().optional(),
    message: z.string().optional(),
  })
  .refine(
    (data) => 'ok' in data || 'affected' in data || 'processed' in data,
    'Invalid admin action response'
  )
  .passthrough()

export const mfaStatusSchema = z.object({
  enabled: z.boolean(),
  has_secret: z.boolean().optional(),
})

export const mfaSetupSchema = z.object({
  secret: z.string().min(1),
  otpauth_url: z.string().min(1),
  issuer: z.string().optional(),
  account: z.string().optional(),
})

export type AdminUser = z.infer<typeof adminUserSchema>
export type AdminListUsersResponse = z.infer<typeof adminListUsersResponseSchema>
export type RegistrationStatus = z.infer<typeof registrationStatusSchema>
export type AdminUserRolesResponse = z.infer<typeof adminUserRolesResponseSchema>
export type AdminActionResponse = z.infer<typeof adminActionResponseSchema>
export type MfaStatus = z.infer<typeof mfaStatusSchema>
export type MfaSetup = z.infer<typeof mfaSetupSchema>
