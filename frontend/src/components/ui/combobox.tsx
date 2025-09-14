import * as React from 'react'
import { Button } from '@/components/ui/button'
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover'
import { Command, CommandEmpty, CommandGroup, CommandInput, CommandItem, CommandList } from '@/components/ui/command'
import { cn } from '@/lib/utils'
import { ChevronsUpDown } from 'lucide-react'

type ComboboxItem = {
  label: string
  value: string
  rightSlot?: React.ReactNode
}

type ComboboxProps = {
  items: ComboboxItem[]
  value?: string
  onChange: (value: string) => void
  placeholder?: string
  emptyText?: string
  triggerText?: string
  className?: string
  disabled?: boolean
}

export const Combobox: React.FC<ComboboxProps> = ({
  items,
  value,
  onChange,
  placeholder = 'Search…',
  emptyText = 'No results found',
  triggerText,
  className,
  disabled,
}) => {
  const [open, setOpen] = React.useState(false)
  const selected = items.find((i) => i.value === value)

  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <Button
          type="button"
          variant="outline"
          role="combobox"
          aria-expanded={open}
          className={cn('justify-between w-[320px]', className)}
          disabled={disabled}
        >
          {selected ? selected.label : triggerText || 'Select…'}
          <ChevronsUpDown className="ml-2 h-4 w-4 shrink-0 opacity-50" />
        </Button>
      </PopoverTrigger>
      <PopoverContent className="p-0 w-[360px]">
        <Command>
          <CommandInput placeholder={placeholder} />
          <CommandList>
            <CommandEmpty>{emptyText}</CommandEmpty>
            <CommandGroup>
              {items.map((i) => (
                <CommandItem
                  key={i.value}
                  value={i.label}
                  onSelect={() => {
                    onChange(i.value)
                    setOpen(false)
                  }}
                >
                  <span className="flex-1">{i.label}</span>
                  {i.rightSlot}
                </CommandItem>
              ))}
            </CommandGroup>
          </CommandList>
        </Command>
      </PopoverContent>
    </Popover>
  )
}

