import { useState } from 'react'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'
import { Label } from '@/components/ui/label'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Checkbox } from '@/components/ui/checkbox'
import { Input } from '@/components/ui/input'
import { exportNote, exportNotes, type ExportOptions } from '@/lib/export-utils'
import { Note } from '@/services/api'
import { toast } from 'sonner'
import { Download, FileText, FileCode, FileType } from 'lucide-react'

interface ExportDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  notes: Note[]
  selectedNote?: Note | null
  mode: 'single' | 'multiple'
}

export function ExportDialog({ open, onOpenChange, notes, selectedNote, mode }: ExportDialogProps) {
  const [format, setFormat] = useState<'markdown' | 'html' | 'txt'>('markdown')
  const [includeMetadata, setIncludeMetadata] = useState(true)
  const [filename, setFilename] = useState('')
  const [isExporting, setIsExporting] = useState(false)

  const handleExport = async () => {
    setIsExporting(true)

    const options: ExportOptions = {
      format,
      includeMetadata,
      filename: filename.trim() || undefined,
    }

    try {
      if (mode === 'single' && selectedNote) {
        await exportNote(selectedNote, options)
        toast.success(`Note exported as ${format.toUpperCase()}`)
      } else if (mode === 'multiple' && notes.length > 0) {
        await exportNotes(notes, options)
        toast.success(`${notes.length} notes exported as ${format.toUpperCase()}`)
      }

      onOpenChange(false)
      setFilename('')
    } catch (error) {
      console.error('Export failed:', error)
      toast.error('Failed to export notes')
    } finally {
      setIsExporting(false)
    }
  }

  const formatIcons = {
    markdown: <FileText className="h-4 w-4" />,
    html: <FileCode className="h-4 w-4" />,
    txt: <FileType className="h-4 w-4" />,
  }

  const formatDescriptions = {
    markdown: 'Markdown format with formatting preserved',
    html: 'HTML document with styling',
    txt: 'Plain text without formatting',
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-[500px]">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Download className="h-5 w-5" />
            Export {mode === 'single' ? 'Note' : `${notes.length} Notes`}
          </DialogTitle>
          <DialogDescription>
            {mode === 'single'
              ? 'Choose a format to export your note.'
              : `Export ${notes.length} selected notes to a single file.`}
          </DialogDescription>
        </DialogHeader>

        <div className="grid gap-4 py-4">
          {/* Format Selection */}
          <div className="grid gap-2">
            <Label htmlFor="format">Export Format</Label>
            <Select value={format} onValueChange={(value: any) => setFormat(value)}>
              <SelectTrigger id="format">
                <SelectValue placeholder="Select format" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="markdown">
                  <div className="flex items-center gap-2">
                    {formatIcons.markdown}
                    <span>Markdown (.md)</span>
                  </div>
                </SelectItem>
                <SelectItem value="html">
                  <div className="flex items-center gap-2">
                    {formatIcons.html}
                    <span>HTML (.html)</span>
                  </div>
                </SelectItem>
                <SelectItem value="txt">
                  <div className="flex items-center gap-2">
                    {formatIcons.txt}
                    <span>Plain Text (.txt)</span>
                  </div>
                </SelectItem>
              </SelectContent>
            </Select>
            <p className="text-sm text-muted-foreground">{formatDescriptions[format]}</p>
          </div>

          {/* Filename */}
          <div className="grid gap-2">
            <Label htmlFor="filename">Filename (optional)</Label>
            <Input
              id="filename"
              placeholder="Leave empty for auto-generated name"
              value={filename}
              onChange={(e) => setFilename(e.target.value)}
            />
            <p className="text-xs text-muted-foreground">
              Extension will be added automatically based on format
            </p>
          </div>

          {/* Options */}
          <div className="flex items-center space-x-2">
            <Checkbox
              id="metadata"
              checked={includeMetadata}
              onCheckedChange={(checked) => setIncludeMetadata(checked as boolean)}
            />
            <Label
              htmlFor="metadata"
              className="text-sm font-normal cursor-pointer"
            >
              Include metadata (created/modified dates)
            </Label>
          </div>
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={isExporting}>
            Cancel
          </Button>
          <Button onClick={handleExport} disabled={isExporting}>
            {isExporting ? (
              <>
                <Download className="mr-2 h-4 w-4 animate-spin" />
                Exporting...
              </>
            ) : (
              <>
                <Download className="mr-2 h-4 w-4" />
                Export
              </>
            )}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
