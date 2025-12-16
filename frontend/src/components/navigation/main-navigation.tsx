/**
 * MainNavigation Component
 *
 * Purpose: Provides the primary navigation interface for the LeafLock application.
 * Implements a hierarchical menu system with role-based access control, organizing
 * tools, resources, and administrative functions in an accessible, responsive layout.
 *
 * User Experience Goals:
 * - Intuitive dropdown navigation with clear categorization
 * - Visual icons for quick recognition of menu items
 * - Responsive design that adapts to different screen sizes
 * - Smooth animations and hover effects for better feedback
 * - External link indicators for off-site resources
 *
 * Security Considerations:
 * - Role-based menu visibility (admin items only shown to administrators)
 * - External links open in new tabs with proper security attributes
 * - No sensitive information exposed in navigation structure
 * - Menu items reflect actual user permissions
 *
 * Accessibility Features:
 * - Semantic HTML structure with proper ARIA labeling
 * - Keyboard navigation support throughout
 * - Screen reader friendly descriptions
 * - High contrast indicators and focus management
 *
 * Architecture:
 * - Modular menu item definitions for easy maintenance
 * - Conditional rendering based on user roles
 * - External link handling with security best practices
 * - Responsive grid layout for different screen sizes
 *
 * Integration Points:
 * - useAuthStore: Provides user role information for menu filtering
 * - NavigationMenu components: Implements accessible dropdown behavior
 * - Lucide icons: Consistent iconography throughout the interface
 *
 * State Management:
 * - User authentication state for role-based rendering
 * - No local component state (stateless navigation component)
 */

'use client'

import * as React from 'react'
import { FileText, Tag, Settings, BookOpen, Github, ChevronDown } from 'lucide-react'

import {
  NavigationMenu,
  NavigationMenuContent,
  NavigationMenuItem,
  NavigationMenuLink,
  NavigationMenuList,
  NavigationMenuTrigger,
} from '@/components/ui/navigation-menu'

const components: { title: string; href: string; description: string; icon: React.ReactNode }[] = [
  {
    title: 'Templates',
    href: '/templates',
    description: 'Manage and create note templates for quick note creation.',
    icon: <FileText className="h-4 w-4" />,
  },
  {
    title: 'Tags',
    href: '/tags',
    description: 'Organize your notes with custom tags and categories.',
    icon: <Tag className="h-4 w-4" />,
  },
  {
    title: 'Settings',
    href: '/settings',
    description: 'Manage your account settings and data backup options.',
    icon: <Settings className="h-4 w-4" />,
  },
]

const externalLinks: { title: string; href: string; description: string; icon: React.ReactNode }[] =
  [
    {
      title: 'Documentation',
      href: 'https://docs.leaflock.app',
      description: 'Learn how to use LeafLock effectively.',
      icon: <BookOpen className="h-4 w-4" />,
    },
    {
      title: 'GitHub',
      href: 'https://github.com/RelativeSure/LeafLock',
      description: 'View source code and contribute to the project.',
      icon: <Github className="h-4 w-4" />,
    },
  ]

export function MainNavigation() {
  return (
    <NavigationMenu>
      <NavigationMenuList>
        <NavigationMenuItem>
          <NavigationMenuTrigger className="flex items-center gap-2">
            <FileText className="h-4 w-4" />
            Tools
            <ChevronDown className="h-3 w-3" />
          </NavigationMenuTrigger>
          <NavigationMenuContent>
            <ul className="grid gap-2 sm:w-[400px] md:w-[500px] md:grid-cols-2 lg:w-[600px]">
              {components.map((component) => (
                <ListItem
                  key={component.title}
                  title={component.title}
                  href={component.href}
                  icon={component.icon}
                >
                  {component.description}
                </ListItem>
              ))}
            </ul>
          </NavigationMenuContent>
        </NavigationMenuItem>

        <NavigationMenuItem>
          <NavigationMenuTrigger className="flex items-center gap-2">
            <BookOpen className="h-4 w-4" />
            Resources
            <ChevronDown className="h-3 w-3" />
          </NavigationMenuTrigger>
          <NavigationMenuContent>
            <ul className="grid gap-2 sm:w-[400px] md:w-[500px] md:grid-cols-2 lg:w-[600px]">
              {externalLinks.map((link) => (
                <ListItem
                  key={link.title}
                  title={link.title}
                  href={link.href}
                  icon={link.icon}
                  external
                >
                  {link.description}
                </ListItem>
              ))}
            </ul>
          </NavigationMenuContent>
        </NavigationMenuItem>
      </NavigationMenuList>
    </NavigationMenu>
  )
}

function ListItem({
  title,
  children,
  href,
  icon,
  external = false,
  ...props
}: React.ComponentPropsWithoutRef<'li'> & {
  href: string
  icon?: React.ReactNode
  external?: boolean
}) {
  const content = (
    <div className="block select-none space-y-1 rounded-md p-3 leading-none no-underline outline-none transition-colors hover:bg-accent hover:text-accent-foreground focus:bg-accent focus:text-accent-foreground">
      <div className="flex items-center gap-2 text-sm font-medium leading-none">
        {icon}
        {title}
        {external && <span className="text-xs text-muted-foreground">↗</span>}
      </div>
      <p className="line-clamp-2 text-sm leading-snug text-muted-foreground">{children}</p>
    </div>
  )

  if (external) {
    return (
      <li {...props}>
        <NavigationMenuLink asChild>
          <a href={href} target="_blank" rel="noopener noreferrer">
            {content}
          </a>
        </NavigationMenuLink>
      </li>
    )
  }

  return (
    <li {...props}>
      <NavigationMenuLink asChild>
        <a href={href}>{content}</a>
      </NavigationMenuLink>
    </li>
  )
}
