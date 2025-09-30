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
import { resolveApiBaseUrl } from '@/utils/network'
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
  const [storageInfo, setStorageInfo] = useState<{
    storage_used: number
    storage_limit: number
    storage_remaining: number
    usage_percentage: number
  } | null>(null)
  const [storageError, setStorageError] = useState<string | null>(null)
  const fileInputRef = useRef<HTMLInputElement>(null)

  const API_BASE_URL = resolveApiBaseUrl()

  // Fetch storage information
  const fetchStorageInfo = useCallback(async () => {
    const token = localStorage.getItem('token')
    if (!token) return

    try {
      const response = await fetch(`${API_BASE_URL}/api/v1/user/storage`, {
        headers: {
          'Authorization': `Bearer ${token}`,
        },
      })

      if (response.ok) {
        const data = await response.json()
        setStorageInfo(data)
        setStorageError(null)
      } else {
        setStorageError('Failed to load storage information')
      }
    } catch (error) {
      setStorageError('Failed to load storage information')
    }
  }, [API_BASE_URL])

  // Validate file size and content
  const validateFile = (file: File): string | null => {
    // Check file size (max 100KB per file for text)
    if (file.size > 100 * 1024) {
      return 'File too large (max 100KB per file)'
    }

    // Check file type
    const allowedTypes = ['text/plain', 'text/markdown', 'text/html', 'application/json']
    const allowedExtensions = ['.md', '.txt', '.html', '.json']

    const hasValidType = allowedTypes.includes(file.type)
    const hasValidExtension = allowedExtensions.some(ext => file.name.toLowerCase().endsWith(ext))

    if (!hasValidType && !hasValidExtension) {
      return 'Invalid file type. Only .md, .txt, .html, and .json files are allowed'
    }

    return null
  }

  // Check if adding files would exceed storage limit
  const checkStorageLimit = (files: File[]): string | null => {
    if (!storageInfo) return null

    const totalSize = files.reduce((sum, file) => sum + file.size, 0)
    const currentSelectedSize = selectedFiles.reduce((sum, file) => sum + file.size, 0)

    if (storageInfo.storage_remaining < totalSize + currentSelectedSize) {
      const remainingMB = (storageInfo.storage_remaining / (1024 * 1024)).toFixed(1)
      const requiredMB = ((totalSize + currentSelectedSize) / (1024 * 1024)).toFixed(1)
      return `Not enough storage space. Available: ${remainingMB} MB, Required: ${requiredMB} MB`
    }

    return null
  }

  // Format bytes to human readable
  const formatBytes = (bytes: number): string => {
    if (bytes === 0) return '0 Bytes'
    const k = 1024
    const sizes = ['Bytes', 'KB', 'MB', 'GB']
    const i = Math.floor(Math.log(bytes) / Math.log(k))
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i]
  }

  // Load storage info when dialog opens
  React.useEffect(() => {
    if (isOpen) {
      fetchStorageInfo()
    }
  }, [isOpen, fetchStorageInfo])

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
      const files = Array.from(e.dataTransfer.files)

      // Validate each file
      const validFiles: File[] = []
      const errors: string[] = []

      for (const file of files) {
        const validationError = validateFile(file)
        if (validationError) {
          errors.push(`${file.name}: ${validationError}`)
        } else {
          validFiles.push(file)
        }
      }

      // Check storage limit for valid files
      if (validFiles.length > 0) {
        const storageError = checkStorageLimit(validFiles)
        if (storageError) {
          errors.push(storageError)
        } else {
          setSelectedFiles(prev => [...prev, ...validFiles])
        }
      }

      // Show errors if any
      if (errors.length > 0) {
        alert(`File validation errors:\n${errors.join('\n')}`)
      }
    }
  }, [validateFile, checkStorageLimit, selectedFiles])

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files) {
      const files = Array.from(e.target.files)

      // Validate each file
      const validFiles: File[] = []
      const errors: string[] = []

      for (const file of files) {
        const validationError = validateFile(file)
        if (validationError) {
          errors.push(`${file.name}: ${validationError}`)
        } else {
          validFiles.push(file)
        }
      }

      // Check storage limit for valid files
      if (validFiles.length > 0) {
        const storageError = checkStorageLimit(validFiles)
        if (storageError) {
          errors.push(storageError)
        } else {
          setSelectedFiles(prev => [...prev, ...validFiles])
        }
      }

      // Show errors if any
      if (errors.length > 0) {
        alert(`File validation errors:\n${errors.join('\n')}`)
      }

      // Clear the input so the same file can be selected again
      e.target.value = ''
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
      // Refresh storage info after successful import
      await fetchStorageInfo()
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

        {/* Storage Information */}
        {storageInfo && (
          <div className="bg-gray-50 rounded-lg p-4 space-y-2">
            <div className="flex justify-between items-center">
              <span className="text-sm font-medium">Storage Usage</span>
              <span className="text-sm text-gray-600">
                {formatBytes(storageInfo.storage_used)} of {formatBytes(storageInfo.storage_limit)}
              </span>
            </div>
            <div className="w-full bg-gray-200 rounded-full h-2">
              <div
                className={`h-2 rounded-full transition-all ${
                  storageInfo.usage_percentage > 90 ? 'bg-red-500' :
                  storageInfo.usage_percentage > 75 ? 'bg-yellow-500' : 'bg-green-500'
                }`}
                style={{ width: `${Math.min(storageInfo.usage_percentage, 100)}%` }}
              />
            </div>
            <div className="text-xs text-gray-500">
              {storageInfo.usage_percentage.toFixed(1)}% used • {formatBytes(storageInfo.storage_remaining)} remaining
            </div>
          </div>
        )}

        {storageError && (
          <div className="bg-red-50 border border-red-200 rounded-lg p-3 text-red-700 text-sm">
            {storageError}
          </div>
        )}

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
                Supports .md, .txt, .html, and .json files (max 100KB per file)
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
