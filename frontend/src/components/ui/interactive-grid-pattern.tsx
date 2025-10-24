'use client'
import React, { useState, useEffect, useRef } from 'react'
import { cn } from '@/lib/utils'

interface InteractiveGridPatternProps extends React.SVGProps<SVGSVGElement> {
  width?: number
  height?: number
  className?: string
  squaresClassName?: string
}

const rainbowColors = [
  'fill-red-500/40 stroke-red-400/70',
  'fill-orange-500/40 stroke-orange-400/70',
  'fill-yellow-500/40 stroke-yellow-400/70',
  'fill-green-500/40 stroke-green-400/70',
  'fill-blue-500/40 stroke-blue-400/70',
  'fill-indigo-500/40 stroke-indigo-400/70',
  'fill-purple-500/40 stroke-purple-400/70',
  'fill-pink-500/40 stroke-pink-400/70',
  'fill-cyan-500/40 stroke-cyan-400/70',
  'fill-teal-500/40 stroke-teal-400/70',
]

export function InteractiveGridPattern({
  width = 50,
  height = 50,
  className,
  squaresClassName,
  ...props
}: InteractiveGridPatternProps) {
  const [hoveredSquare, setHoveredSquare] = useState<number | null>(null)
  const [dimensions, setDimensions] = useState({ horizontal: 0, vertical: 0 })
  const [squareColors, setSquareColors] = useState<Map<number, string>>(new Map())
  const svgRef = useRef<SVGSVGElement>(null)

  useEffect(() => {
    const updateDimensions = () => {
      if (svgRef.current) {
        const rect = svgRef.current.getBoundingClientRect()
        const horizontal = Math.ceil(rect.width / width) + 1
        const vertical = Math.ceil(rect.height / height) + 1
        setDimensions({ horizontal, vertical })
      }
    }

    updateDimensions()
    window.addEventListener('resize', updateDimensions)
    return () => window.removeEventListener('resize', updateDimensions)
  }, [width, height])

  const handleMouseEnter = (index: number) => {
    setHoveredSquare(index)
    if (!squareColors.has(index)) {
      // Use deterministic color selection based on index to avoid impure Math.random() during render
      const colorIndex = index % rainbowColors.length
      const selectedColor = rainbowColors[colorIndex]
      setSquareColors(new Map(squareColors.set(index, selectedColor)))
    }
  }

  const { horizontal, vertical } = dimensions

  return (
    <svg ref={svgRef} className={cn('absolute inset-0 h-full w-full', className)} {...props}>
      {Array.from({ length: horizontal * vertical }).map((_, index) => {
        const x = (index % horizontal) * width
        const y = Math.floor(index / horizontal) * height
        const colorClass = squareColors.get(index) || ''

        return (
          <rect
            key={index}
            x={x}
            y={y}
            width={width}
            height={height}
            className={cn(
              'stroke-slate-700/40 transition-all duration-100 ease-in-out [&:not(:hover)]:duration-1000',
              hoveredSquare === index ? colorClass : 'fill-slate-800/20',
              squaresClassName
            )}
            onMouseEnter={() => handleMouseEnter(index)}
            onMouseLeave={() => setHoveredSquare(null)}
          />
        )
      })}
    </svg>
  )
}

export type { InteractiveGridPatternProps }
