import { useRef, useEffect, KeyboardEvent, ClipboardEvent } from 'react'
import { Input } from '../ui/input'

interface TotpInputProps {
  value: string
  onChange: (value: string) => void
  onComplete?: (value: string) => void
  disabled?: boolean
  error?: boolean
  length?: number
}

export function TotpInput({
  value,
  onChange,
  onComplete,
  disabled = false,
  error = false,
  length = 6,
}: TotpInputProps) {
  const inputRefs = useRef<(HTMLInputElement | null)[]>([])

  useEffect(() => {
    // Auto-focus first input on mount
    inputRefs.current[0]?.focus()
  }, [])

  useEffect(() => {
    // Call onComplete when all digits are entered
    if (value.length === length && onComplete) {
      onComplete(value)
    }
  }, [value, length, onComplete])

  const handleChange = (index: number, digit: string) => {
    // Only allow digits
    if (digit && !/^\d$/.test(digit)) {
      return
    }

    const newValue = value.split('')
    newValue[index] = digit
    const newValueStr = newValue.join('').slice(0, length)
    onChange(newValueStr)

    // Auto-advance to next input
    if (digit && index < length - 1) {
      inputRefs.current[index + 1]?.focus()
    }
  }

  const handleKeyDown = (index: number, e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Backspace') {
      if (!value[index] && index > 0) {
        // Move to previous input if current is empty
        inputRefs.current[index - 1]?.focus()
      } else {
        // Clear current digit
        const newValue = value.split('')
        newValue[index] = ''
        onChange(newValue.join(''))
      }
    } else if (e.key === 'ArrowLeft' && index > 0) {
      inputRefs.current[index - 1]?.focus()
    } else if (e.key === 'ArrowRight' && index < length - 1) {
      inputRefs.current[index + 1]?.focus()
    }
  }

  const handlePaste = (e: ClipboardEvent<HTMLInputElement>) => {
    e.preventDefault()
    const pastedData = e.clipboardData.getData('text/plain').replace(/\D/g, '')

    if (pastedData.length === length) {
      onChange(pastedData)
      // Focus last input after paste
      inputRefs.current[length - 1]?.focus()
    }
  }

  const handleFocus = (index: number) => {
    inputRefs.current[index]?.select()
  }

  return (
    <div className="flex gap-2 justify-center">
      {Array.from({ length }, (_, index) => (
        <Input
          key={index}
          ref={(el) => (inputRefs.current[index] = el)}
          type="text"
          inputMode="numeric"
          maxLength={1}
          value={value[index] || ''}
          onChange={(e) => handleChange(index, e.target.value)}
          onKeyDown={(e) => handleKeyDown(index, e)}
          onPaste={handlePaste}
          onFocus={() => handleFocus(index)}
          disabled={disabled}
          className={`w-12 h-12 text-center text-lg font-semibold ${
            error ? 'border-red-500 focus-visible:ring-red-500' : ''
          }`}
          aria-label={`Digit ${index + 1} of ${length}`}
          aria-invalid={error}
          aria-describedby={error ? 'totp-error' : undefined}
        />
      ))}
    </div>
  )
}
