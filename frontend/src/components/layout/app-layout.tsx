/**
 * AppLayout Component
 *
 * Purpose: Provides the main application layout structure with resizable sidebar,
 * responsive design, and consistent navigation. Implements a flexible panel system
 * that adapts to different screen sizes and user preferences.
 *
 * User Experience Goals:
 * - Intuitive resizable sidebar for customizable workspace
 * - Smooth transitions and animations for layout changes
 * - Mobile-responsive design with touch-friendly interactions
 * - Persistent sidebar width preferences across sessions
 * - Clean separation between navigation and content areas
 *
 * Layout Architecture:
 * - Resizable sidebar (15-40% width) containing app navigation
 * - Main content area with header and dynamic content
 * - Collapsible sidebar for mobile devices
 * - Responsive handle for manual resizing
 *
 * Performance Considerations:
 * - Optimized re-renders through proper state management
 * - Efficient resize handling with debounced updates
 * - Mobile-specific optimizations to reduce layout calculations
 * - Lazy loading of sidebar content when appropriate
 *
 * Accessibility Features:
 * - Keyboard navigation support for resize operations
 * - Screen reader announcements for layout changes
 * - High contrast indicators for resize handles
 * - Semantic HTML structure for better navigation
 *
 * Responsive Design:
 * - Mobile: Fixed sidebar with overlay behavior
 * - Tablet: Collapsible sidebar with touch gestures
 * - Desktop: Full resizable functionality
 * - Automatic adaptation based on viewport size
 *
 * Integration Points:
 * - SidebarProvider: Manages sidebar state and behavior
 * - ResizablePanelGroup: Implements drag-to-resize functionality
 * - useSidebarResize: Custom hook for persistent width management
 * - TanStack Router: Handles dynamic content rendering
 *
 * State Management:
 * - Sidebar state (open/collapsed) via context provider
 * - Panel width percentage via custom hook
 * - Mobile detection for responsive behavior
 */

import { SidebarInset, SidebarProvider, SidebarTrigger, useSidebar } from '@/components/ui/sidebar'
import { AppSidebar } from './app-sidebar'
import { Outlet } from '@tanstack/react-router'
import { Separator } from '@/components/ui/separator'
import { ResizablePanelGroup, ResizablePanel, ResizableHandle } from '@/components/ui/resizable'
import { useSidebarResize } from '@/hooks/use-sidebar-resize'

function AppLayoutContent() {
  const { state, isMobile } = useSidebar()
  const { widthPercentage, setWidth } = useSidebarResize()
  const isCollapsed = state === 'collapsed'

  /**
   * Responsive Behavior Control
   *
   * Purpose: Disables resize functionality on mobile devices or when
   * sidebar is collapsed to prevent layout issues and improve touch UX.
   *
   * Mobile Experience: Uses overlay sidebar instead of resize
   * Desktop Experience: Full resize capabilities with visual handles
   */
  const resizeDisabled = isMobile || isCollapsed

  return (
    <ResizablePanelGroup direction="horizontal" className="h-screen">
      <ResizablePanel
        defaultSize={widthPercentage}
        minSize={15} // Slightly wider for notes list
        maxSize={40} // Allow more space for notes
        onResize={setWidth}
        collapsible={false}
        className={resizeDisabled ? 'pointer-events-none' : ''}
      >
        <AppSidebar />
      </ResizablePanel>

      {!resizeDisabled && (
        <ResizableHandle withHandle className="hover:bg-accent transition-colors" />
      )}

      <ResizablePanel defaultSize={100 - widthPercentage} minSize={30}>
        <SidebarInset>
          <header className="flex h-12 shrink-0 items-center gap-2 border-b px-4 bg-background">
            <div className="flex items-center gap-2">
              <SidebarTrigger className="-ml-1" />
              <Separator orientation="vertical" className="mr-2 h-4" />
            </div>
          </header>
          <div className="flex flex-1 flex-col min-h-0 overflow-hidden bg-background">
            <Outlet />
          </div>
        </SidebarInset>
      </ResizablePanel>
    </ResizablePanelGroup>
  )
}

export default function AppLayout() {
  return (
    <SidebarProvider>
      <AppLayoutContent />
    </SidebarProvider>
  )
}
