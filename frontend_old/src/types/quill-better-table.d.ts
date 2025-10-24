declare module 'quill-better-table' {
  import { Quill } from 'quill'

  interface QuillBetterTableOptions {
    operationMenu?: {
      items?: Record<string, { text: string }>
    }
  }

  class QuillBetterTable {
    static keyboardBindings: any
    constructor(quill: Quill, options: QuillBetterTableOptions)
    insertTable(rows: number, cols: number): void
  }

  export default QuillBetterTable
}
