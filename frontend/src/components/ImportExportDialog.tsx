import React, { useState, useRef, useCallback } from 'react'
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from './ui/dialog'
import { Button } from './ui/button'
import { Upload, Download, FileText, File, X } from 'lucide-react'
interface Note {
  id: string
  title: string
  content: string
  created_at: string
  updated_at: string
  title_encrypted?: string
  content_encrypted?: string
}

interface ImportExportDialogProps {
  noteId?: string
  trigger?: React.ReactNode
  notes?: Note[]
  setNotes?: React.Dispatch<React.SetStateAction<Note[]>>
  onImportSuccess?: () => void
}

export function ImportExportDialog({
  noteId,
  trigger,
  notes: _notes,
  setNotes,
  onImportSuccess
}: ImportExportDialogProps) {
  const [isOpen, setIsOpen] = useState(false)
  const [isImporting, setIsImporting] = useState(false)
  const [isExporting, setIsExporting] = useState(false)
  const [dragActive, setDragActive] = useState(false)
  const [selectedFiles, setSelectedFiles] = useState<File[]>([])
  const [exportFormat, setExportFormat] = useState<'markdown' | 'text' | 'html' | 'json'>('markdown')
  const fileInputRef = useRef<HTMLInputElement>(null)

  const API_BASE_URL = (import.meta as any).env.VITE_API_URL || 'http://localhost:8080'

  const handleDrag = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    e.stopPropagation()
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setDragActive(true)
    } else if (e.type === 'dragleave') {
      setDragActive(false)
    }
  }, [])

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    e.stopPropagation()
    setDragActive(false)

    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      const files = Array.from(e.dataTransfer.files).filter(file =>
        file.type === 'text/plain' ||
        file.type === 'text/markdown' ||
        file.type === 'text/html' ||
        file.type === 'application/json' ||
        file.name.endsWith('.md') ||
        file.name.endsWith('.txt') ||
        file.name.endsWith('.html') ||
        file.name.endsWith('.json')
      )
      setSelectedFiles(prev => [...prev, ...files])
    }
  }, [])

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files) {
      const files = Array.from(e.target.files).filter(file =>
        file.type === 'text/plain' ||
        file.type === 'text/markdown' ||
        file.type === 'text/html' ||
        file.type === 'application/json' ||
        file.name.endsWith('.md') ||
        file.name.endsWith('.txt') ||
        file.name.endsWith('.html') ||
        file.name.endsWith('.json')
      )
      setSelectedFiles(prev => [...prev, ...files])
    }
  }

  const removeFile = (index: number) => {
    setSelectedFiles(prev => prev.filter((_, i) => i !== index))
  }

  const handleImport = async () => {
    if (selectedFiles.length === 0) return

    setIsImporting(true)
    const token = localStorage.getItem('token')

    try {
      if (selectedFiles.length === 1) {
        // Single file import
        const formData = new FormData()
        formData.append('file', selectedFiles[0])

        const response = await fetch(`${API_BASE_URL}/api/v1/notes/import`, {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${token}`,
          },
          body: formData,
        })

        if (!response.ok) {
          const error = await response.json()
          throw new Error(error.error || 'Import failed')
        }

        const data = await response.json()
        if (setNotes && data.note) {
          setNotes(prev => [data.note, ...prev])
        }
      } else {
        // Bulk import
        const formData = new FormData()
        selectedFiles.forEach(file => {
          formData.append('files', file)
        })

        const response = await fetch(`${API_BASE_URL}/api/v1/notes/bulk-import`, {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${token}`,
          },
          body: formData,
        })

        if (!response.ok) {
          const error = await response.json()
          throw new Error(error.error || 'Bulk import failed')
        }

        const data = await response.json()
        if (setNotes && data.imported_notes) {
          setNotes(prev => [...data.imported_notes, ...prev])
        }
      }

      // Call the callback if provided
      if (onImportSuccess) {
        onImportSuccess()
      }
      setSelectedFiles([])
      alert('Import successful!')
    } catch (error) {
      console.error('Import error:', error)
      alert(error instanceof Error ? error.message : 'Import failed')
    } finally {
      setIsImporting(false)
    }
  }

  const handleExport = async () => {
    if (!noteId) return

    setIsExporting(true)
    const token = localStorage.getItem('token')

    try {
      const response = await fetch(`${API_BASE_URL}/api/v1/notes/${noteId}/export`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ format: exportFormat }),
      })

      if (!response.ok) {
        const error = await response.json()
        throw new Error(error.error || 'Export failed')
      }

      const data = await response.json()

      // Create download
      const blob = new Blob([data.content], { type: 'text/plain' })
      const url = window.URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = data.filename
      document.body.appendChild(a)
      a.click()
      window.URL.revokeObjectURL(url)
      document.body.removeChild(a)

      alert('Export successful!')
    } catch (error) {
      console.error('Export error:', error)
      alert(error instanceof Error ? error.message : 'Export failed')
    } finally {
      setIsExporting(false)
    }
  }

  const getFileIcon = (file: File) => {
    if (file.name.endsWith('.md') || file.type === 'text/markdown') {
      return <FileText className="w-4 h-4 text-blue-500" />
    }
    return <File className="w-4 h-4 text-gray-500" />
  }

  return (
    <Dialog open={isOpen} onOpenChange={setIsOpen}>
      <DialogTrigger asChild>
        {trigger || (
          <Button variant="outline" size="sm">
            <Upload className="w-4 h-4 mr-2" />
            Import/Export
          </Button>
        )}
      </DialogTrigger>
      <DialogContent className="max-w-2xl">
        <DialogHeader>
          <DialogTitle>Import & Export Notes</DialogTitle>
        </DialogHeader>

        <div className="space-y-6">
          {/* Import Section */}
          <div className="space-y-4">
            <h3 className="text-lg font-medium flex items-center">
              <Upload className="w-5 h-5 mr-2" />
              Import Notes
            </h3>

            {/* Drag and Drop Area */}
            <div
              className={`border-2 border-dashed rounded-lg p-8 text-center transition-colors ${
                dragActive
                  ? 'border-blue-500 bg-blue-50'
                  : 'border-gray-300 hover:border-gray-400'
              }`}
              onDragEnter={handleDrag}
              onDragLeave={handleDrag}
              onDragOver={handleDrag}
              onDrop={handleDrop}
            >
              <Upload className="w-12 h-12 mx-auto text-gray-400 mb-4" />
              <p className="text-lg mb-2">Drop files here or click to select</p>
              <p className="text-sm text-gray-500 mb-4">
                Supports .md, .txt, .html, and .json files
              </p>
              <Button
                variant="outline"
                onClick={() => fileInputRef.current?.click()}
              >
                Select Files
              </Button>
              <input
                ref={fileInputRef}
                type="file"
                multiple
                accept=".md,.txt,.html,.json,text/plain,text/markdown,text/html,application/json"
                onChange={handleFileSelect}
                className="hidden"
              />
            </div>

            {/* Selected Files */}
            {selectedFiles.length > 0 && (
              <div className="space-y-2">
                <h4 className="font-medium">Selected Files ({selectedFiles.length})</h4>
                <div className="max-h-40 overflow-y-auto space-y-1">
                  {selectedFiles.map((file, index) => (
                    <div
                      key={index}
                      className="flex items-center justify-between p-2 bg-gray-50 rounded"
                    >
                      <div className="flex items-center space-x-2">
                        {getFileIcon(file)}
                        <span className="text-sm">{file.name}</span>
                        <span className="text-xs text-gray-500">
                          ({(file.size / 1024).toFixed(1)} KB)
                        </span>
                      </div>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => removeFile(index)}
                      >
                        <X className="w-4 h-4" />
                      </Button>
                    </div>
                  ))}
                </div>
                <Button
                  onClick={handleImport}
                  disabled={isImporting}
                  className="w-full"
                >
                  {isImporting ? 'Importing...' : `Import ${selectedFiles.length} File(s)`}
                </Button>
              </div>
            )}
          </div>

          {/* Export Section */}
          {noteId && (
            <div className="space-y-4 border-t pt-6">
              <h3 className="text-lg font-medium flex items-center">
                <Download className="w-5 h-5 mr-2" />
                Export Current Note
              </h3>

              <div className="space-y-3">
                <div>
                  <label className="block text-sm font-medium mb-2">Export Format</label>
                  <div className="grid grid-cols-2 gap-2">
                    {(['markdown', 'text', 'html', 'json'] as const).map((format) => (
                      <button
                        key={format}
                        onClick={() => setExportFormat(format)}
                        className={`p-3 border rounded-lg text-left transition-colors ${
                          exportFormat === format
                            ? 'border-blue-500 bg-blue-50'
                            : 'border-gray-200 hover:border-gray-300'
                        }`}
                      >
                        <div className="font-medium capitalize">{format}</div>
                        <div className="text-sm text-gray-500">
                          {format === 'markdown' && '.md file'}
                          {format === 'text' && 'Plain text .txt'}
                          {format === 'html' && 'HTML document'}
                          {format === 'json' && 'JSON export'}
                        </div>
                      </button>
                    ))}
                  </div>
                </div>

                <Button
                  onClick={handleExport}
                  disabled={isExporting}
                  className="w-full"
                >
                  {isExporting ? 'Exporting...' : `Export as ${exportFormat.toUpperCase()}`}
                </Button>
              </div>
            </div>
          )}
        </div>
      </DialogContent>
    </Dialog>
  )
}