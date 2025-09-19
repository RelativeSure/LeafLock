import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, fireEvent, within } from '@testing-library/react'
import AdminPage from './AdminPage'

type MockApi = {
  adminListUsers: ReturnType<typeof vi.fn>
  adminGetRegistration: ReturnType<typeof vi.fn>
  adminSetAdmin: ReturnType<typeof vi.fn>
  adminGetUserRoles: ReturnType<typeof vi.fn>
  adminAssignRole: ReturnType<typeof vi.fn>
  adminRemoveRole: ReturnType<typeof vi.fn>
  adminBulkRole: ReturnType<typeof vi.fn>
  adminBulkAdmin: ReturnType<typeof vi.fn>
  adminExportUsersCsv: ReturnType<typeof vi.fn>
}

const createMockApi = (overrides: Partial<Record<keyof MockApi, any>> = {}): MockApi => ({
  adminListUsers: vi.fn().mockResolvedValue({ users: [], total: 0 }),
  adminGetRegistration: vi.fn().mockResolvedValue({ enabled: true }),
  adminSetAdmin: vi.fn().mockResolvedValue({ ok: true }),
  adminGetUserRoles: vi.fn().mockResolvedValue({ roles: [] }),
  adminAssignRole: vi.fn().mockResolvedValue({ ok: true }),
  adminRemoveRole: vi.fn().mockResolvedValue({ ok: true }),
  adminBulkRole: vi.fn().mockResolvedValue({ ok: true }),
  adminBulkAdmin: vi.fn().mockResolvedValue({ ok: true }),
  adminExportUsersCsv: vi.fn().mockResolvedValue(new Blob()),
  ...overrides,
})

const baseUser = {
  user_id: '00000000-0000-0000-0000-000000000001',
  email: 'mail@rasmusj.dk',
  mfa_enabled: false,
  roles: [] as string[],
  created_at: '2025-09-17T12:10:11.000Z',
  last_login: '2025-09-18T13:39:35.000Z',
  registration_ip: '198.51.100.10',
  last_ip: '198.51.100.10',
}

describe('AdminPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('highlights admins added via allowlist', async () => {
    const mockApi = createMockApi({
      adminListUsers: vi.fn().mockResolvedValue({
        users: [
          {
            ...baseUser,
            is_admin: true,
            admin_via_allowlist: true,
          },
        ],
        total: 1,
      }),
    })

    render(<AdminPage api={mockApi} onBack={vi.fn()} />)

    expect(await screen.findByText('Admin Dashboard')).toBeInTheDocument()

    await screen.findByText(/Admin: Yes \(allowlist override\)/i)
    const badge = await screen.findByText(/admin • allowlist/i)
    expect(badge).toBeInTheDocument()

    expect(mockApi.adminListUsers).toHaveBeenCalledTimes(1)
    expect(mockApi.adminGetRegistration).toHaveBeenCalledTimes(1)
  })

  it('grants admin rights through the Make Admin button', async () => {
    const initialUser = {
      ...baseUser,
      is_admin: false,
      admin_via_allowlist: false,
    }
    const elevatedUser = {
      ...baseUser,
      is_admin: true,
      admin_via_allowlist: false,
    }

    const adminListUsers = vi.fn()
    adminListUsers
      .mockResolvedValueOnce({ users: [initialUser], total: 1 })
      .mockResolvedValueOnce({ users: [elevatedUser], total: 1 })

    const mockApi = createMockApi({
      adminListUsers,
    })

    render(<AdminPage api={mockApi} onBack={vi.fn()} />)

    expect(await screen.findByText('Admin Dashboard')).toBeInTheDocument()

    const makeAdminButton = await screen.findByRole('button', { name: /make admin/i })
    fireEvent.click(makeAdminButton)

    await waitFor(() =>
      expect(mockApi.adminSetAdmin).toHaveBeenCalledWith(initialUser.user_id, true)
    )
    await waitFor(() => expect(adminListUsers).toHaveBeenCalledTimes(2))

    await screen.findByText(/Admin: Yes\\b/i)
    const table = await screen.findByRole('table')
    const rows = within(table).getAllByRole('row')
    expect(rows[1]).toHaveTextContent(/admin/i)
  })
})
