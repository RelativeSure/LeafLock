import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import React from 'react'
import { AppSidebar } from '../app-sidebar'
import { useNotesStore } from '@/stores/notesStore'
import { useClerkAuthStore } from '@/stores/clerkAuthStore'

const mockNavigate = vi.fn()
const mockLogout = vi.fn()
const createNoteMock = vi.fn()
const createFolderMock = vi.fn()
const selectFolderMock = vi.fn()
const selectTagMock = vi.fn()
const selectNoteMock = vi.fn()

vi.mock('@/stores/notesStore', () => ({
  useNotesStore: vi.fn(),
}))

vi.mock('@/stores/authStore', () => ({
  useClerkAuthStore: vi.fn(),
}))

vi.mock('@tanstack/react-router', () => ({
  Link: ({ children, to, ...props }: any) => (
    <a href={to} data-testid={`link-${to}`} {...props}>
      {children}
    </a>
  ),
  useNavigate: () => mockNavigate,
  useLocation: () => ({ pathname: '/' }),
}))

vi.mock('@/components/ui/sidebar', () => ({
  Sidebar: ({ children, ...props }: any) => (
    <div data-testid="sidebar" {...props}>
      {children}
    </div>
  ),
  SidebarContent: ({ children }: any) => <div data-testid="sidebar-content">{children}</div>,
  SidebarFooter: ({ children }: any) => <div data-testid="sidebar-footer">{children}</div>,
  SidebarHeader: ({ children }: any) => <div data-testid="sidebar-header">{children}</div>,
  SidebarMenu: ({ children }: any) => <ul data-testid="sidebar-menu">{children}</ul>,
  SidebarMenuItem: ({ children }: any) => <li data-testid="sidebar-menu-item">{children}</li>,
  SidebarMenuButton: ({ children, onClick, isActive, tooltip, asChild, ...props }: any) => {
    if (asChild) {
      return React.cloneElement(children, {
        'data-active': isActive,
        'data-tooltip': tooltip,
        ...props,
      })
    }
    return (
      <button
        onClick={onClick}
        data-active={isActive}
        data-tooltip={tooltip}
        data-testid="sidebar-menu-button"
        {...props}
      >
        {children}
      </button>
    )
  },
  SidebarRail: () => <div data-testid="sidebar-rail" />,
  SidebarSeparator: () => <hr data-testid="sidebar-separator" />,
  SidebarGroup: ({ children, className }: any) => (
    <div data-testid="sidebar-group" className={className}>
      {children}
    </div>
  ),
  SidebarGroupLabel: ({ children, asChild }: any) => {
    if (asChild) {
      return React.cloneElement(children, { 'data-testid': 'sidebar-group-label' })
    }
    return <div data-testid="sidebar-group-label">{children}</div>
  },
  SidebarGroupContent: ({ children }: any) => (
    <div data-testid="sidebar-group-content">{children}</div>
  ),
  SidebarGroupAction: ({ children, onClick, title, disabled }: any) => (
    <button onClick={onClick} title={title} disabled={disabled} data-testid="sidebar-group-action">
      {children}
    </button>
  ),
  SidebarInput: (props: any) => <input data-testid="sidebar-input" {...props} />,
}))

vi.mock('@/components/ui/collapsible', () => ({
  Collapsible: ({ children, defaultOpen }: any) => (
    <div data-testid="collapsible" data-default-open={defaultOpen}>
      {children}
    </div>
  ),
  CollapsibleContent: ({ children }: any) => (
    <div data-testid="collapsible-content">{children}</div>
  ),
  CollapsibleTrigger: ({ children }: any) => (
    <button data-testid="collapsible-trigger">{children}</button>
  ),
}))

vi.mock('@/components/ui/dropdown-menu', () => ({
  DropdownMenu: ({ children }: any) => <div data-testid="dropdown-menu">{children}</div>,
  DropdownMenuContent: ({ children }: any) => (
    <div data-testid="dropdown-menu-content">{children}</div>
  ),
  DropdownMenuItem: ({ children, onClick }: any) => (
    <button onClick={onClick} data-testid="dropdown-menu-item">
      {children}
    </button>
  ),
  DropdownMenuTrigger: ({ children, asChild }: any) => {
    if (asChild) {
      return React.cloneElement(children, { 'data-testid': 'dropdown-trigger' })
    }
    return <button data-testid="dropdown-trigger">{children}</button>
  },
}))

vi.mock('@/components/ui/dialog', () => ({
  Dialog: ({ children, open, onOpenChange }: any) => (
    <div data-testid="dialog" data-open={open}>
      {React.Children.map(children, (child) =>
        React.isValidElement(child) ? React.cloneElement(child, { onOpenChange } as any) : child
      )}
    </div>
  ),
  DialogContent: ({ children }: any) => <div data-testid="dialog-content">{children}</div>,
  DialogDescription: ({ children }: any) => <p data-testid="dialog-description">{children}</p>,
  DialogHeader: ({ children }: any) => <div data-testid="dialog-header">{children}</div>,
  DialogTitle: ({ children }: any) => <h2 data-testid="dialog-title">{children}</h2>,
  DialogTrigger: ({ children, asChild, onOpenChange }: any) => {
    const handleClick = () => onOpenChange?.(true)
    if (asChild) {
      return React.cloneElement(children, { onClick: handleClick })
    }
    return (
      <button onClick={handleClick} data-testid="dialog-trigger">
        {children}
      </button>
    )
  },
  DialogFooter: ({ children }: any) => <div data-testid="dialog-footer">{children}</div>,
}))

vi.mock('@/components/ui/input', () => ({
  Input: (props: any) => <input data-testid="input" {...props} />,
}))

vi.mock('@/components/ui/label', () => ({
  Label: ({ children, htmlFor }: any) => <label htmlFor={htmlFor}>{children}</label>,
}))

vi.mock('@/components/ui/button', () => ({
  Button: ({ children, onClick, ...props }: any) => (
    <button onClick={onClick} data-testid="button" {...props}>
      {children}
    </button>
  ),
}))

vi.mock('@/components/ui/user-avatar', () => ({
  UserAvatar: ({ user, size }: any) => (
    <div data-testid="user-avatar" data-size={size}>
      {user?.name || 'Avatar'}
    </div>
  ),
}))

vi.mock('../sidebar-note-list', () => ({
  SidebarNoteList: () => <div data-testid="sidebar-note-list">Note List</div>,
}))

vi.mock('lucide-react', () => ({
  Home: () => <span data-testid="icon-home">home</span>,
  Settings: () => <span data-testid="icon-settings">settings</span>,
  Shield: () => <span data-testid="icon-shield">shield</span>,
  Tag: () => <span data-testid="icon-tag">tag</span>,
  Plus: () => <span data-testid="icon-plus">plus</span>,
  LogOut: () => <span data-testid="icon-logout">logout</span>,
  Leaf: () => <span data-testid="icon-leaf">leaf</span>,
  ChevronRight: () => <span data-testid="icon-chevron">chevron</span>,
  Trash2: () => <span data-testid="icon-trash">trash</span>,
}))

const mockUser = {
  id: 'user-1',
  email: 'test@example.com',
  name: 'Test User',
  isAdmin: false,
}

const mockAdminUser = {
  ...mockUser,
  isAdmin: true,
}

const mockFolders = [
  {
    id: 'folder-1',
    name: 'Work',
    color: '#3b82f6',
    createdAt: '2024-01-01',
    updatedAt: '2024-01-01',
  },
  {
    id: 'folder-2',
    name: 'Personal',
    color: '#10b981',
    createdAt: '2024-01-01',
    updatedAt: '2024-01-01',
  },
]

const mockTags = [
  { id: 'tag-1', name: 'important', createdAt: '2024-01-01', updatedAt: '2024-01-01' },
  { id: 'tag-2', name: 'todo', createdAt: '2024-01-01', updatedAt: '2024-01-01' },
]

describe('AppSidebar', () => {
  let consoleErrorSpy: ReturnType<typeof vi.spyOn>

  beforeEach(() => {
    vi.clearAllMocks()
    createNoteMock.mockResolvedValue({ id: 'new-note-id' })
    createFolderMock.mockResolvedValue({ id: 'new-folder-id' })

    vi.mocked(useNotesStore).mockReturnValue({
      notes: [],
      folders: [],
      tags: [],
      selectedNote: null,
      selectedFolder: null,
      selectNote: selectNoteMock,
      selectFolder: selectFolderMock,
      selectTag: selectTagMock,
      createNote: createNoteMock,
      createFolder: createFolderMock,
      isLoading: false,
    } as any)

    vi.mocked(useClerkAuthStore).mockReturnValue({
      user: mockUser,
      logout: mockLogout,
      isAuthenticated: true,
    } as any)

    consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => undefined)
  })

  afterEach(() => {
    consoleErrorSpy.mockRestore()
  })

  describe('Rendering', () => {
    it('should render the sidebar with header', () => {
      render(<AppSidebar />)
      expect(screen.getByTestId('sidebar')).toBeInTheDocument()
      expect(screen.getByTestId('sidebar-header')).toBeInTheDocument()
    })

    it('should render LeafLock branding', () => {
      render(<AppSidebar />)
      expect(screen.getByText('LeafLock')).toBeInTheDocument()
      expect(screen.getByText('Secure Notes')).toBeInTheDocument()
    })

    it('should render All Notes button', () => {
      render(<AppSidebar />)
      expect(screen.getByText('All Notes')).toBeInTheDocument()
    })

    it('should render Trash button', () => {
      render(<AppSidebar />)
      expect(screen.getByText('Trash')).toBeInTheDocument()
    })

    it('should render the note list component', () => {
      render(<AppSidebar />)
      expect(screen.getByTestId('sidebar-note-list')).toBeInTheDocument()
    })

    it('should render Settings link', () => {
      render(<AppSidebar />)
      const settingsLinks = screen.getAllByText('Settings')
      expect(settingsLinks.length).toBeGreaterThan(0)
    })

    it('should render user info in footer', () => {
      render(<AppSidebar />)
      const userNames = screen.getAllByText('Test User')
      expect(userNames.length).toBeGreaterThan(0)
      expect(screen.getByText('test@example.com')).toBeInTheDocument()
    })

    it('should render user avatar', () => {
      render(<AppSidebar />)
      expect(screen.getByTestId('user-avatar')).toBeInTheDocument()
    })
  })

  describe('Admin visibility', () => {
    it('should not show Admin Console for non-admin users', () => {
      render(<AppSidebar />)
      expect(screen.queryByText('Admin Console')).not.toBeInTheDocument()
    })

    it('should show Admin Console for admin users', () => {
      vi.mocked(useClerkAuthStore).mockReturnValue({
        user: mockAdminUser,
        logout: mockLogout,
        isAuthenticated: true,
      } as any)

      render(<AppSidebar />)
      expect(screen.getByText('Admin Console')).toBeInTheDocument()
    })
  })

  describe('Folders', () => {
    it('should render Folders section', () => {
      render(<AppSidebar />)
      expect(screen.getByText('Folders')).toBeInTheDocument()
    })

    it('should show "No folders" when folders list is empty', () => {
      render(<AppSidebar />)
      expect(screen.getByText('No folders')).toBeInTheDocument()
    })

    it('should render folder list when folders exist', () => {
      vi.mocked(useNotesStore).mockReturnValue({
        notes: [],
        folders: mockFolders,
        tags: [],
        selectedNote: null,
        selectedFolder: null,
        selectNote: selectNoteMock,
        selectFolder: selectFolderMock,
        selectTag: selectTagMock,
        createNote: createNoteMock,
        createFolder: createFolderMock,
        isLoading: false,
      } as any)

      render(<AppSidebar />)
      expect(screen.getByText('Work')).toBeInTheDocument()
      expect(screen.getByText('Personal')).toBeInTheDocument()
    })

    it('should call selectFolder when clicking a folder', () => {
      vi.mocked(useNotesStore).mockReturnValue({
        notes: [],
        folders: mockFolders,
        tags: [],
        selectedNote: null,
        selectedFolder: null,
        selectNote: selectNoteMock,
        selectFolder: selectFolderMock,
        selectTag: selectTagMock,
        createNote: createNoteMock,
        createFolder: createFolderMock,
        isLoading: false,
      } as any)

      render(<AppSidebar />)
      const workButton = screen.getByText('Work').closest('button')
      fireEvent.click(workButton!)

      expect(selectFolderMock).toHaveBeenCalledWith('folder-1')
      expect(mockNavigate).toHaveBeenCalledWith({ to: '/' })
    })
  })

  describe('Tags', () => {
    it('should render Tags section', () => {
      render(<AppSidebar />)
      expect(screen.getByText('Tags')).toBeInTheDocument()
    })

    it('should show "No tags" when tags list is empty', () => {
      render(<AppSidebar />)
      expect(screen.getByText('No tags')).toBeInTheDocument()
    })

    it('should render tag list when tags exist', () => {
      vi.mocked(useNotesStore).mockReturnValue({
        notes: [],
        folders: [],
        tags: mockTags,
        selectedNote: null,
        selectedFolder: null,
        selectNote: selectNoteMock,
        selectFolder: selectFolderMock,
        selectTag: selectTagMock,
        createNote: createNoteMock,
        createFolder: createFolderMock,
        isLoading: false,
      } as any)

      render(<AppSidebar />)
      expect(screen.getByText('important')).toBeInTheDocument()
      expect(screen.getByText('todo')).toBeInTheDocument()
    })

    it('should call selectTag when clicking a tag', () => {
      vi.mocked(useNotesStore).mockReturnValue({
        notes: [],
        folders: [],
        tags: mockTags,
        selectedNote: null,
        selectedFolder: null,
        selectNote: selectNoteMock,
        selectFolder: selectFolderMock,
        selectTag: selectTagMock,
        createNote: createNoteMock,
        createFolder: createFolderMock,
        isLoading: false,
      } as any)

      render(<AppSidebar />)
      const importantButton = screen.getByText('important').closest('button')
      fireEvent.click(importantButton!)

      expect(selectTagMock).toHaveBeenCalledWith('important')
      expect(mockNavigate).toHaveBeenCalledWith({ to: '/' })
    })
  })

  describe('Navigation', () => {
    it('should navigate to home when clicking All Notes', () => {
      render(<AppSidebar />)
      const allNotesButton = screen.getByText('All Notes').closest('button')
      fireEvent.click(allNotesButton!)

      expect(selectFolderMock).toHaveBeenCalledWith(null)
      expect(mockNavigate).toHaveBeenCalledWith({ to: '/' })
    })
  })

  describe('Create Note', () => {
    it('should call createNote when clicking new note button', async () => {
      render(<AppSidebar />)
      const newNoteButtons = screen.getAllByTestId('sidebar-group-action')
      const newNoteButton = newNoteButtons.find((btn) => btn.getAttribute('title') === 'New Note')
      fireEvent.click(newNoteButton!)

      await waitFor(() => {
        expect(createNoteMock).toHaveBeenCalledWith({})
      })
    })

    it('should navigate after creating note', async () => {
      render(<AppSidebar />)
      const newNoteButtons = screen.getAllByTestId('sidebar-group-action')
      const newNoteButton = newNoteButtons.find((btn) => btn.getAttribute('title') === 'New Note')
      fireEvent.click(newNoteButton!)

      await waitFor(() => {
        expect(mockNavigate).toHaveBeenCalledWith({ to: '/' })
      })
    })

    it('should handle create note error', async () => {
      createNoteMock.mockRejectedValue(new Error('Failed to create'))

      render(<AppSidebar />)
      const newNoteButtons = screen.getAllByTestId('sidebar-group-action')
      const newNoteButton = newNoteButtons.find((btn) => btn.getAttribute('title') === 'New Note')
      fireEvent.click(newNoteButton!)

      await waitFor(() => {
        expect(consoleErrorSpy).toHaveBeenCalledWith('Failed to create note:', expect.any(Error))
      })
    })

    it('should disable new note button when loading', () => {
      vi.mocked(useNotesStore).mockReturnValue({
        notes: [],
        folders: [],
        tags: [],
        selectedNote: null,
        selectedFolder: null,
        selectNote: selectNoteMock,
        selectFolder: selectFolderMock,
        selectTag: selectTagMock,
        createNote: createNoteMock,
        createFolder: createFolderMock,
        isLoading: true,
      } as any)

      render(<AppSidebar />)
      const newNoteButtons = screen.getAllByTestId('sidebar-group-action')
      const newNoteButton = newNoteButtons.find((btn) => btn.getAttribute('title') === 'New Note')
      expect(newNoteButton).toHaveAttribute('disabled')
    })
  })

  describe('Create Folder Dialog', () => {
    it('should render create folder dialog', () => {
      render(<AppSidebar />)
      expect(screen.getByTestId('dialog')).toBeInTheDocument()
    })

    it('should have folder name input', () => {
      render(<AppSidebar />)
      const inputs = screen.getAllByTestId('input')
      expect(inputs.length).toBeGreaterThan(0)
    })

    it('should render color picker buttons', () => {
      render(<AppSidebar />)
      const colorButtons = screen.getAllByRole('button').filter((btn) => {
        const style = btn.getAttribute('style')
        return style && style.includes('background-color')
      })
      expect(colorButtons.length).toBe(6)
    })

    it('should change color when clicking a color picker button', async () => {
      render(<AppSidebar />)
      const colorButtons = screen.getAllByRole('button').filter((btn) => {
        const style = btn.getAttribute('style')
        return style && style.includes('background-color')
      })

      // Click a different color (purple - #8b5cf6)
      const purpleButton = colorButtons.find((btn) =>
        btn.getAttribute('style')?.includes('rgb(139, 92, 246)')
      )
      if (purpleButton) {
        fireEvent.click(purpleButton)
      }

      // Now create a folder to verify the color was changed
      const input = screen.getAllByTestId('input')[0]
      fireEvent.change(input, { target: { value: 'Purple Folder' } })

      const createButtons = screen.getAllByText('Create Folder')
      const createButton = createButtons.find((btn) => btn.tagName === 'BUTTON')
      fireEvent.click(createButton!)

      await waitFor(() => {
        expect(createFolderMock).toHaveBeenCalledWith({
          name: 'Purple Folder',
          color: '#8b5cf6',
        })
      })
    })

    it('should call createFolder with name and color', async () => {
      render(<AppSidebar />)

      const input = screen.getAllByTestId('input')[0]
      fireEvent.change(input, { target: { value: 'New Folder' } })

      const createButtons = screen.getAllByText('Create Folder')
      const createButton = createButtons.find((btn) => btn.tagName === 'BUTTON')
      fireEvent.click(createButton!)

      await waitFor(() => {
        expect(createFolderMock).toHaveBeenCalledWith({
          name: 'New Folder',
          color: '#3b82f6',
        })
      })
    })

    it('should not create folder with empty name', async () => {
      render(<AppSidebar />)

      const createButtons = screen.getAllByText('Create Folder')
      const createButton = createButtons.find((btn) => btn.tagName === 'BUTTON')
      fireEvent.click(createButton!)

      await waitFor(() => {
        expect(createFolderMock).not.toHaveBeenCalled()
      })
    })
  })

  describe('Logout', () => {
    it('should render logout menu item', () => {
      render(<AppSidebar />)
      expect(screen.getByText('Log out')).toBeInTheDocument()
    })

    it('should call logout and navigate on logout click', () => {
      render(<AppSidebar />)
      const logoutButton = screen.getByText('Log out').closest('button')
      fireEvent.click(logoutButton!)

      expect(mockLogout).toHaveBeenCalled()
      expect(mockNavigate).toHaveBeenCalledWith({ to: '/login' })
    })
  })

  describe('Dropdown menu', () => {
    it('should navigate to settings from dropdown', () => {
      render(<AppSidebar />)
      const accountButton = screen.getByText('Account').closest('button')
      fireEvent.click(accountButton!)

      expect(mockNavigate).toHaveBeenCalledWith({ to: '/settings' })
    })
  })

  describe('Trash button', () => {
    it('should allow clicking Trash button without errors', () => {
      render(<AppSidebar />)
      const trashButton = screen.getByText('Trash').closest('button')

      // Should not throw error when clicked (currently a placeholder/no-op)
      expect(() => fireEvent.click(trashButton!)).not.toThrow()
    })
  })

  describe('Empty folders array edge case', () => {
    it('should show "No folders" with explicitly empty array', () => {
      vi.mocked(useNotesStore).mockReturnValue({
        notes: [],
        folders: [], // Explicitly empty array
        tags: [],
        selectedNote: null,
        selectedFolder: null,
        selectNote: selectNoteMock,
        selectFolder: selectFolderMock,
        selectTag: selectTagMock,
        createNote: createNoteMock,
        createFolder: createFolderMock,
        isLoading: false,
      } as any)

      render(<AppSidebar />)
      expect(screen.getByText('No folders')).toBeInTheDocument()
    })
  })
})
