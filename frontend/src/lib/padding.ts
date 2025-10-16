/**
 * Semantic Padding System for LeafLock
 *
 * Centralized padding utilities for consistent spacing across the application.
 * All values are based on Tailwind's spacing scale (1 unit = 0.25rem = 4px).
 *
 * Usage:
 * import { padding } from '@/lib/padding'
 * <div className={padding.page}>...</div>
 */

export const padding = {
  // ==================== MICRO SPACING (0-4px) ====================
  /** No padding: p-0 (0px) */
  none: 'p-0',

  /** Tiny padding: p-0.5 (2px) - Used for icon buttons, small badges */
  tiny: 'p-0.5',

  /** Extra small padding: p-1 (4px) - Used for dropdown menus, tiny buttons */
  xs: 'p-1',

  // ==================== SMALL SPACING (8-12px) ====================
  /** Small padding: p-2 (8px) - List items, small cards, errors */
  sm: 'p-2',

  /** Medium padding: p-3 (12px) - Card sections, notices, footers */
  md: 'p-3',

  // ==================== MEDIUM SPACING (16-24px) ====================
  /** Large padding: p-4 (16px) - Page containers, content areas */
  lg: 'p-4',

  /** Extra large padding: p-6 (24px) - Card headers, dialogs, settings */
  xl: 'p-6',

  // ==================== LARGE SPACING (32px+) ====================
  /** 2XL padding: p-8 (32px) - Empty states, large containers */
  '2xl': 'p-8',

  // ==================== DIRECTIONAL PADDING ====================
  directional: {
    /** Horizontal only: px-2 (8px horizontal) */
    xSm: 'px-2',
    /** Horizontal only: px-3 (12px horizontal) */
    xMd: 'px-3',
    /** Horizontal only: px-4 (16px horizontal) */
    xLg: 'px-4',
    /** Horizontal only: px-6 (24px horizontal) */
    xXl: 'px-6',

    /** Vertical only: py-2 (8px vertical) */
    ySm: 'py-2',
    /** Vertical only: py-3 (12px vertical) */
    yMd: 'py-3',
    /** Vertical only: py-4 (16px vertical) */
    yLg: 'py-4',
    /** Vertical only: py-6 (24px vertical) */
    yXl: 'py-6',
    /** Vertical only: py-8 (32px vertical) */
    y2xl: 'py-8',

    /** Top only: pt-2 (8px top) */
    tSm: 'pt-2',
    /** Top only: pt-4 (16px top) */
    tLg: 'pt-4',
    /** Top only: pt-6 (24px top) */
    tXl: 'pt-6',

    /** Bottom only: pb-3 (12px bottom) */
    bMd: 'pb-3',
    /** Bottom only: pb-4 (16px bottom) */
    bLg: 'pb-4',

    /** Left only: pl-9 (36px left) - Search inputs with icons */
    lSearch: 'pl-9',
    /** Left only: pl-10 (40px left) - Search inputs with icons (alternate) */
    lSearchAlt: 'pl-10',
  },

  // ==================== COMPONENT-SPECIFIC PADDING ====================
  component: {
    /** Page container: p-4 md:p-6 - Main page wrapper with responsive padding */
    page: 'p-4 md:p-6',

    /** Page horizontal: px-4 - Page horizontal padding only */
    pageHorizontal: 'px-4',

    /** Card header: p-6 - Standard card header */
    cardHeader: 'p-6',

    /** Card content: p-6 pt-0 - Card content without top padding */
    cardContent: 'p-6 pt-0',

    /** Card content with padding: p-6 - Card content with all padding */
    cardContentFull: 'p-6',

    /** Dialog content: p-6 - Dialog/modal content */
    dialogContent: 'p-6',

    /** List item small: p-2 - Small list items (tags, folders) */
    listItemSm: 'p-2',

    /** List item medium: p-3 - Medium list items (share items) */
    listItemMd: 'p-3',

    /** List item large: p-4 - Large list items (notes) */
    listItemLg: 'p-4',

    /** List item with mobile touch: p-4 md:p-4 py-6 md:py-4 - Enhanced mobile touch targets */
    listItemTouch: 'p-4 md:p-4 py-6 md:py-4',

    /** Empty state: py-8 - Empty state messages */
    emptyState: 'py-8',

    /** Error inline: p-2 - Small inline errors */
    errorInline: 'p-2',

    /** Error box: p-3 - Medium error boxes */
    errorBox: 'p-3',

    /** Error full: p-4 - Full-width error boxes */
    errorFull: 'p-4',

    /** Section header: pb-3 - Section headers with bottom padding */
    sectionHeader: 'pb-3',

    /** Section header large: pb-4 - Larger section headers */
    sectionHeaderLg: 'pb-4',

    /** Section spacing: pt-4 - Spacing between sections */
    sectionSpacing: 'pt-4',

    /** Footer: p-3 - Footer padding */
    footer: 'p-3',

    /** Header section: p-3 - Header sections in lists */
    headerSection: 'p-3',
  },

  // ==================== FORM ELEMENTS ====================
  form: {
    /** Standard input: px-3 py-1 - Default input field */
    input: 'px-3 py-1',

    /** Large input: px-3 py-2 - Larger input/textarea */
    inputLg: 'px-3 py-2',

    /** Input with icon: pl-10 pr-10 - Input with left/right icons */
    inputIcon: 'pl-10 pr-10',

    /** Input with left icon: pl-10 - Input with left icon only */
    inputIconLeft: 'pl-10',

    /** Button default: px-4 py-2 - Default button padding */
    button: 'px-4 py-2',

    /** Button small: px-3 py-1.5 - Small button */
    buttonSm: 'px-3 py-1.5',

    /** Button large: px-6 py-2 - Large button */
    buttonLg: 'px-6 py-2',

    /** Icon button: p-2 - Button with icon only */
    iconButton: 'p-2',

    /** Icon button small: p-1 - Small icon button */
    iconButtonSm: 'p-1',

    /** Icon button none: p-0 - Icon button with no padding */
    iconButtonNone: 'p-0',
  },

  // ==================== EDITOR & RICH TEXT ====================
  editor: {
    /** Toolbar container: p-1.5 md:p-2 - Editor toolbar */
    toolbarContainer: 'p-1.5 md:p-2',

    /** Toolbar button: p-2.5 md:p-2 - Mobile-first touch target for toolbar buttons */
    toolbarButton: 'p-2.5 md:p-2',

    /** Editor content: px-3 py-2 - Main editor content area */
    editorContent: 'px-3 py-2',

    /** Editor wrapper: px-4 py-4 - Editor container wrapper */
    editorWrapper: 'px-4 py-4',

    /** Title bar: px-4 py-2.5 - Editor title bar */
    titleBar: 'px-4 py-2.5',

    /** Inline code: px-1 py-0.5 - Inline code elements */
    inlineCode: 'px-1 py-0.5',

    /** Inline code alternate: px-1.5 py-0.5 - Inline code (alternate) */
    inlineCodeAlt: 'px-1.5 py-0.5',

    /** Code block: p-4 - Code block padding */
    codeBlock: 'p-4',

    /** Code block small: p-2 - Small code block */
    codeBlockSm: 'p-2',
  },

  // ==================== MOBILE-FIRST RESPONSIVE ====================
  mobile: {
    /** Mobile touch target: p-2.5 md:p-2 - Ensures 44px minimum touch target */
    touchTarget: 'p-2.5 md:p-2',

    /** Mobile touch vertical: py-6 md:py-4 - Enhanced vertical touch target */
    touchVertical: 'py-6 md:py-4',

    /** Mobile page: p-4 md:p-6 - Responsive page padding */
    page: 'p-4 md:p-6',
  },

  // ==================== SPECIAL USE CASES ====================
  special: {
    /** Dropdown menu: p-1 - Dropdown menu containers */
    dropdownMenu: 'p-1',

    /** Menu item: px-3 py-2 - Menu item padding */
    menuItem: 'px-3 py-2',

    /** Badge small: px-1.5 py-0.5 - Small badge padding */
    badgeSm: 'px-1.5 py-0.5',

    /** Tooltip: px-2 py-1 - Tooltip padding */
    tooltip: 'px-2 py-1',

    /** Search icon spacing: pl-9 or pl-10 - Left padding for search inputs with icons */
    searchIconLeft: 'pl-10',

    /** Announcement banner: p-4 - Top announcement bar */
    announcementBanner: 'p-4',

    /** Announcement toolbar: px-4 py-2 - Announcement action toolbar */
    announcementToolbar: 'px-4 py-2',

    /** Info box: p-3 or p-4 - Info/warning boxes */
    infoBox: 'p-4',

    /** Circular icon container: p-2 - Circular background for icons */
    circularIcon: 'p-2',
  },
} as const

// Type exports for autocomplete
export type PaddingKey = keyof typeof padding
export type ComponentPaddingKey = keyof typeof padding.component
export type FormPaddingKey = keyof typeof padding.form
export type EditorPaddingKey = keyof typeof padding.editor
export type MobilePaddingKey = keyof typeof padding.mobile
export type SpecialPaddingKey = keyof typeof padding.special
export type DirectionalPaddingKey = keyof typeof padding.directional
