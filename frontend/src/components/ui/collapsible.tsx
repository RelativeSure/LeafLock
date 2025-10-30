'use client'

import * as React from 'react'
import * as CollapsiblePrimitive from '@radix-ui/react-collapsible'

const Collapsible = React.forwardRef<
  React.ElementRef<typeof CollapsiblePrimitive.Root>,
  React.ComponentPropsWithoutRef<typeof CollapsiblePrimitive.Root>
>(({ ...props }, ref) => {
  return <CollapsiblePrimitive.Root ref={ref} data-slot="collapsible" {...props} />
})
Collapsible.displayName = CollapsiblePrimitive.Root.displayName

const CollapsibleTrigger = React.forwardRef<
  React.ElementRef<typeof CollapsiblePrimitive.CollapsibleTrigger>,
  React.ComponentPropsWithoutRef<typeof CollapsiblePrimitive.CollapsibleTrigger>
>(({ ...props }, ref) => {
  return (
    <CollapsiblePrimitive.CollapsibleTrigger ref={ref} data-slot="collapsible-trigger" {...props} />
  )
})
CollapsibleTrigger.displayName = CollapsiblePrimitive.CollapsibleTrigger.displayName

const CollapsibleContent = React.forwardRef<
  React.ElementRef<typeof CollapsiblePrimitive.CollapsibleContent>,
  React.ComponentPropsWithoutRef<typeof CollapsiblePrimitive.CollapsibleContent>
>(({ ...props }, ref) => {
  return (
    <CollapsiblePrimitive.CollapsibleContent ref={ref} data-slot="collapsible-content" {...props} />
  )
})
CollapsibleContent.displayName = CollapsiblePrimitive.CollapsibleContent.displayName

export { Collapsible, CollapsibleTrigger, CollapsibleContent }
