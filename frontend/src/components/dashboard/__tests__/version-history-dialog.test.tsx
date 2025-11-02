import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, act } from '@testing-library/react'
import { VersionHistoryDialog } from '../version-history-dialog'

const getNoteVersions = vi.fn().mockResolvedValue([])

vi.mock('../../stores/notesStore', () => ({
  useNotesStore: vi.fn(() => ({
    createNoteVersion: vi.fn(),
    getNoteVersions,
    restoreNoteVersion: vi.fn(),
    deleteNoteVersion: vi.fn(),
    compareNoteVersions: vi.fn(),
    updateRetentionPolicy: vi.fn(),
  })),
}))

vi.mock('../../hooks/use-toast', () => ({
  useToast: () => ({
    toast: {
      success: vi.fn(),
      error: vi.fn(),
      info: vi.fn(),
    },
  }),
}))

vi.mock('@/components/ui/dialog', () => ({
  Dialog: ({ children }: any) => <div data-testid="dialog-root">{children}</div>,
  DialogContent: ({ children }: any) => <div>{children}</div>,
  DialogHeader: ({ children }: any) => <div>{children}</div>,
  DialogTitle: ({ children }: any) => <h2>{children}</h2>,
  DialogDescription: ({ children }: any) => <p>{children}</p>,
  DialogFooter: ({ children }: any) => <div>{children}</div>,
  DialogTrigger: ({ children, onClick }: any) => (
    <button type="button" onClick={onClick} data-testid="dialog-trigger">
      {children}
    </button>
  ),
}))

vi.mock('@/components/ui/tabs', () => ({
  Tabs: ({ children }: any) => <div>{children}</div>,
  TabsList: ({ children }: any) => <div>{children}</div>,
  TabsTrigger: ({ children, value, onClick }: any) => (
    <button type="button" data-value={value} onClick={onClick}>
      {children}
    </button>
  ),
  TabsContent: ({ children }: any) => <div>{children}</div>,
}))

vi.mock('@/components/ui/scroll-area', () => ({
  ScrollArea: ({ children }: any) => <div>{children}</div>,
}))

vi.mock('@/components/ui/button', () => ({
  Button: ({ children, onClick, ...props }: any) => (
    <button type="button" onClick={onClick} {...props}>
      {children}
    </button>
  ),
}))

vi.mock('@/components/ui/badge', () => ({
  Badge: ({ children }: any) => <span>{children}</span>,
}))

vi.mock('@/components/ui/card', () => ({
  Card: ({ children }: any) => <div>{children}</div>,
  CardHeader: ({ children }: any) => <div>{children}</div>,
  CardTitle: ({ children }: any) => <h3>{children}</h3>,
  CardDescription: ({ children }: any) => <p>{children}</p>,
  CardContent: ({ children }: any) => <div>{children}</div>,
}))

vi.mock('@/components/ui/select', () => ({
  Select: ({ children }: any) => <div>{children}</div>,
  SelectTrigger: ({ children }: any) => <button type="button">{children}</button>,
  SelectContent: ({ children }: any) => <div>{children}</div>,
  SelectItem: ({ children, onSelect }: any) => (
    <div role="option" onClick={onSelect}>
      {children}
    </div>
  ),
  SelectValue: ({ children }: any) => <span>{children}</span>,
}))

vi.mock('@/components/ui/slider', () => ({
  Slider: ({ onValueChange }: any) => (
    <input type="range" onChange={(event) => onValueChange?.([Number(event.target.value)])} />
  ),
}))

vi.mock('@/components/ui/hover-card', () => ({
  HoverCard: ({ children }: any) => <div>{children}</div>,
  HoverCardTrigger: ({ children }: any) => <div>{children}</div>,
  HoverCardContent: ({ children }: any) => <div>{children}</div>,
}))

vi.mock('@/components/ui/alert-dialog', () => ({
  AlertDialog: ({ children }: any) => <div>{children}</div>,
  AlertDialogContent: ({ children }: any) => <div>{children}</div>,
  AlertDialogHeader: ({ children }: any) => <div>{children}</div>,
  AlertDialogTitle: ({ children }: any) => <h4>{children}</h4>,
  AlertDialogDescription: ({ children }: any) => <p>{children}</p>,
  AlertDialogFooter: ({ children }: any) => <div>{children}</div>,
  AlertDialogCancel: ({ children, onClick }: any) => (
    <button type="button" onClick={onClick}>
      {children}
    </button>
  ),
  AlertDialogAction: ({ children, onClick }: any) => (
    <button type="button" onClick={onClick}>
      {children}
    </button>
  ),
}))

vi.mock('lucide-react', () => ({
  History: () => <span />,
  RotateCcw: () => <span />,
  Trash2: () => <span />,
  Clock: () => <span />,
  User: () => <span />,
  FileText: () => <span />,
  Calendar: () => <span />,
  Settings: () => <span />,
  GitCompare: () => <span />,
}))

describe('VersionHistoryDialog', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    getNoteVersions.mockClear()
    getNoteVersions.mockResolvedValue([])
  })

  it('renders trigger content', () => {
    const { getByText } = render(
      <VersionHistoryDialog noteId="note-1" noteTitle="Test Note">
        <span>Open history</span>
      </VersionHistoryDialog>
    )

    expect(getByText('Open history')).toBeInTheDocument()
  })

  it('fetches versions when opened', async () => {
    const { getByTestId } = render(
      <VersionHistoryDialog noteId="note-99" noteTitle="Project Plan">
        <span>Show history</span>
      </VersionHistoryDialog>
    )

    await act(async () => {
      const trigger = getByTestId('dialog-trigger')
      trigger.click()
      await Promise.resolve()
    })

    expect(getNoteVersions).toHaveBeenCalledWith('note-99')
  })
})
