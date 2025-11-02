import { describe, it, expect } from 'vitest'
import '@testing-library/jest-dom'

describe('test-setup', () => {
  it('should have testing-library matchers', () => {
    const element = document.createElement('div')
    element.textContent = 'test'
    expect(element).toBeInTheDocument()
  })

  it('should have document available', () => {
    expect(document).toBeDefined()
    expect(document.body).toBeDefined()
  })

  it('should have window available', () => {
    expect(window).toBeDefined()
    expect(window.document).toBeDefined()
  })

  it('should create elements', () => {
    const div = document.createElement('div')
    div.className = 'test-class'
    expect(div.className).toBe('test-class')
  })

  it('should support localStorage', () => {
    localStorage.setItem('test', 'value')
    expect(localStorage.getItem('test')).toBe('value')
    localStorage.removeItem('test')
  })

  it('should support sessionStorage', () => {
    sessionStorage.setItem('test', 'value')
    expect(sessionStorage.getItem('test')).toBe('value')
    sessionStorage.removeItem('test')
  })
})
