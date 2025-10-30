import * as React from 'react'
import { Slot } from '@radix-ui/react-slot'
import { cva, type VariantProps } from 'class-variance-authority'

import { cn } from '@/lib/utils'
import { Separator } from '@/components/ui/separator'

const ItemGroup = React.forwardRef<HTMLDivElement, React.ComponentProps<'div'>>(
  ({ className, ...props }, ref) => {
    return (
      <div
        ref={ref}
        role="list"
        data-slot="item-group"
        className={cn('group/item-group flex flex-col', className)}
        {...props}
      />
    )
  }
)
ItemGroup.displayName = 'ItemGroup'

const ItemSeparator = React.forwardRef<
  React.ElementRef<typeof Separator>,
  React.ComponentPropsWithoutRef<typeof Separator>
>(({ className, ...props }, ref) => {
  return (
    <Separator
      ref={ref}
      data-slot="item-separator"
      orientation="horizontal"
      className={cn('my-0', className)}
      {...props}
    />
  )
})
ItemSeparator.displayName = 'ItemSeparator'

const itemVariants = cva(
  'group/item [a]:hover:bg-accent/50 focus-visible:border-ring focus-visible:ring-ring/50 [a]:transition-colors flex flex-wrap items-center rounded-md border border-transparent text-sm outline-none transition-colors duration-100 focus-visible:ring-[3px]',
  {
    variants: {
      variant: {
        default: 'bg-transparent',
        outline: 'border-border',
        muted: 'bg-muted/50',
      },
      size: {
        default: 'gap-4 p-4 ',
        sm: 'gap-2.5 px-4 py-3',
      },
    },
    defaultVariants: {
      variant: 'default',
      size: 'default',
    },
  }
)

const Item = React.forwardRef<
  HTMLDivElement,
  React.ComponentProps<'div'> & VariantProps<typeof itemVariants> & { asChild?: boolean }
>(({ className, variant = 'default', size = 'default', asChild = false, ...props }, ref) => {
  const Comp = asChild ? Slot : 'div'
  return (
    <Comp
      ref={ref}
      data-slot="item"
      data-variant={variant}
      data-size={size}
      className={cn(itemVariants({ variant, size, className }))}
      {...props}
    />
  )
})

Item.displayName = 'Item'

const itemMediaVariants = cva(
  'flex shrink-0 items-center justify-center gap-2 group-has-[[data-slot=item-description]]/item:translate-y-0.5 group-has-[[data-slot=item-description]]/item:self-start [&_svg]:pointer-events-none',
  {
    variants: {
      variant: {
        default: 'bg-transparent',
        icon: "bg-muted size-8 rounded-sm border [&_svg:not([class*='size-'])]:size-4",
        image: 'size-10 overflow-hidden rounded-sm [&_img]:size-full [&_img]:object-cover',
      },
    },
    defaultVariants: {
      variant: 'default',
    },
  }
)

const ItemMedia = React.forwardRef<
  HTMLDivElement,
  React.ComponentProps<'div'> & VariantProps<typeof itemMediaVariants>
>(({ className, variant = 'default', ...props }, ref) => {
  return (
    <div
      ref={ref}
      data-slot="item-media"
      data-variant={variant}
      className={cn(itemMediaVariants({ variant, className }))}
      {...props}
    />
  )
})
ItemMedia.displayName = 'ItemMedia'

const ItemContent = React.forwardRef<HTMLDivElement, React.ComponentProps<'div'>>(
  ({ className, ...props }, ref) => {
    return (
      <div
        ref={ref}
        data-slot="item-content"
        className={cn(
          'flex flex-1 flex-col gap-1 [&+[data-slot=item-content]]:flex-none',
          className
        )}
        {...props}
      />
    )
  }
)
ItemContent.displayName = 'ItemContent'

const ItemTitle = React.forwardRef<HTMLDivElement, React.ComponentProps<'div'>>(
  ({ className, ...props }, ref) => {
    return (
      <div
        ref={ref}
        data-slot="item-title"
        className={cn('flex w-fit items-center gap-2 text-sm font-medium leading-snug', className)}
        {...props}
      />
    )
  }
)
ItemTitle.displayName = 'ItemTitle'

const ItemDescription = React.forwardRef<HTMLParagraphElement, React.ComponentProps<'p'>>(
  ({ className, ...props }, ref) => {
    return (
      <p
        ref={ref}
        data-slot="item-description"
        className={cn(
          'text-muted-foreground line-clamp-2 text-balance text-sm font-normal leading-normal',
          '[&>a:hover]:text-primary [&>a]:underline [&>a]:underline-offset-4',
          className
        )}
        {...props}
      />
    )
  }
)
ItemDescription.displayName = 'ItemDescription'

const ItemActions = React.forwardRef<HTMLDivElement, React.ComponentProps<'div'>>(
  ({ className, ...props }, ref) => {
    return (
      <div
        ref={ref}
        data-slot="item-actions"
        className={cn('flex items-center gap-2', className)}
        {...props}
      />
    )
  }
)
ItemActions.displayName = 'ItemActions'

const ItemHeader = React.forwardRef<HTMLDivElement, React.ComponentProps<'div'>>(
  ({ className, ...props }, ref) => {
    return (
      <div
        ref={ref}
        data-slot="item-header"
        className={cn('flex basis-full items-center justify-between gap-2', className)}
        {...props}
      />
    )
  }
)
ItemHeader.displayName = 'ItemHeader'

const ItemFooter = React.forwardRef<HTMLDivElement, React.ComponentProps<'div'>>(
  ({ className, ...props }, ref) => {
    return (
      <div
        ref={ref}
        data-slot="item-footer"
        className={cn('flex basis-full items-center justify-between gap-2', className)}
        {...props}
      />
    )
  }
)
ItemFooter.displayName = 'ItemFooter'

export {
  Item,
  ItemMedia,
  ItemContent,
  ItemActions,
  ItemGroup,
  ItemSeparator,
  ItemTitle,
  ItemDescription,
  ItemHeader,
  ItemFooter,
}
