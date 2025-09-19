import * as React from 'react'
import { Button } from '@/components/ui/button'
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover'
import {
  Command,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
} from '@/components/ui/command'
import { Badge } from '@/components/ui/badge'
import { cn } from '@/lib/utils'
import { Check, ChevronsUpDown } from 'lucide-react'

export type MultiItem = {
  label: string
  value: string
}

type MultiComboboxProps = {
  items: MultiItem[]
  values: string[]
  onChange: (values: string[]) => void
  placeholder?: string
  triggerText?: string
  className?: string
  disabled?: boolean
}

export const MultiCombobox: React.FC<MultiComboboxProps> = ({
  items,
  values,
  onChange,
  placeholder = 'Search…',
  triggerText,
  className,
  disabled,
}) => {
  const [open, setOpen] = React.useState(false)
  const selectedMap = React.useMemo(() => new Set(values), [values])

  const toggle = (val: string) => {
    const next = new Set(selectedMap)
    if (next.has(val)) next.delete(val)
    else next.add(val)
    onChange(Array.from(next))
  }

  const label = React.useMemo(() => {
    if (triggerText) return triggerText
    if (!values.length) return 'Any role'
    if (values.length <= 2) {
      return items
        .filter((i) => selectedMap.has(i.value))
        .map((i) => i.label)
        .join(', ')
    }
    return `${values.length} selected`
  }, [triggerText, values, items, selectedMap])

  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <Button
          type="button"
          variant="outline"
          role="combobox"
          aria-expanded={open}
          className={cn('justify-between w-[280px]', className)}
          disabled={disabled}
        >
          {label}
          <ChevronsUpDown className="ml-2 h-4 w-4 shrink-0 opacity-50" />
        </Button>
      </PopoverTrigger>
      <PopoverContent className="p-0 w-[320px]">
        <Command>
          <CommandInput placeholder={placeholder} />
          <CommandList>
            <CommandEmpty>No results found</CommandEmpty>
            <CommandGroup>
              {items.map((i) => {
                const selected = selectedMap.has(i.value)
                return (
                  <CommandItem key={i.value} value={i.label} onSelect={() => toggle(i.value)}>
                    <Check className={cn('mr-2 h-4 w-4', selected ? 'opacity-100' : 'opacity-0')} />
                    <span className="flex-1">{i.label}</span>
                    {selected && <Badge variant="secondary">selected</Badge>}
                  </CommandItem>
                )
              })}
            </CommandGroup>
          </CommandList>
        </Command>
      </PopoverContent>
    </Popover>
  )
}
