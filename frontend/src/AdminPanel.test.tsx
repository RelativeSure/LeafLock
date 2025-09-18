import { describe, it, expect, vi } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import AdminPanel from './AdminPanel'

describe('AdminPanel', () => {
  it('loads roles, assigns and removes roles, toggles admin', async () => {
    const mockApi = {
      adminListUsers: vi.fn().mockResolvedValue({ users: [], total: 0 }),
      adminGetUserRoles: vi.fn().mockResolvedValue({ roles: ['user'] }),
      adminSetAdmin: vi.fn().mockResolvedValue({ ok: true }),
      adminAssignRole: vi.fn().mockResolvedValue({ ok: true }),
      adminRemoveRole: vi.fn().mockResolvedValue({ ok: true }),
    }

    render(<AdminPanel api={mockApi} />)

    const input = screen.getByPlaceholderText('User ID (UUID)') as HTMLInputElement
    fireEvent.change(input, { target: { value: '00000000-0000-0000-0000-000000000001' } })

    // Load roles
    fireEvent.click(screen.getByText('Load Roles'))
    await waitFor(() => expect(mockApi.adminGetUserRoles).toHaveBeenCalled())
    expect(await screen.findByText(/Current roles/i)).toBeInTheDocument()

    // Assign role
    fireEvent.click(screen.getByText('Assign Role'))
    await waitFor(() => expect(mockApi.adminAssignRole).toHaveBeenCalled())

    // Remove role
    fireEvent.click(screen.getByText('Remove Role'))
    await waitFor(() => expect(mockApi.adminRemoveRole).toHaveBeenCalled())

    // Toggle admin
    fireEvent.click(screen.getByText('Make Admin'))
    await waitFor(() => expect(mockApi.adminSetAdmin).toHaveBeenCalledWith('00000000-0000-0000-0000-000000000001', true))
    fireEvent.click(screen.getByText('Revoke Admin'))
    await waitFor(() => expect(mockApi.adminSetAdmin).toHaveBeenCalledWith('00000000-0000-0000-0000-000000000001', false))
  })

  it('grants admin via quick email helper', async () => {
    const mockApi = {
      adminListUsers: vi.fn().mockResolvedValue({
        users: [
          {
            user_id: '00000000-0000-0000-0000-000000000001',
            email: 'mail@rasmusj.dk',
          },
        ],
        total: 1,
      }),
      adminSetAdmin: vi.fn().mockResolvedValue({ ok: true }),
      adminGetUserRoles: vi.fn().mockResolvedValue({ roles: [] }),
      adminAssignRole: vi.fn(),
      adminRemoveRole: vi.fn(),
    }

    render(<AdminPanel api={mockApi} />)

    const quickInput = await screen.findByPlaceholderText('user@example.com')
    fireEvent.change(quickInput, { target: { value: 'mail@rasmusj.dk' } })
    fireEvent.click(screen.getByText('Grant admin'))

    await waitFor(() => expect(mockApi.adminListUsers).toHaveBeenCalledWith({ q: 'mail@rasmusj.dk', limit: 1, offset: 0 }))
    await waitFor(() => expect(mockApi.adminSetAdmin).toHaveBeenCalledWith('00000000-0000-0000-0000-000000000001', true))
  })
})
