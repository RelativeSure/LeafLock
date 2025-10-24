"use client"

import { createContext, useContext, useState, useEffect, type ReactNode } from "react"
import type { User } from "./types"
import { ActivityLogger } from "./activity-logger"

interface AuthContextType {
  user: User | null
  login: (email: string, password: string) => Promise<{ requiresMFA: boolean }>
  verifyMFA: (code: string) => Promise<boolean>
  logout: () => void
  register: (email: string, password: string, name: string) => Promise<void>
  enableMFA: () => Promise<string>
  disableMFA: () => Promise<void>
  isLoading: boolean
}

const AuthContext = createContext<AuthContextType | undefined>(undefined)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null)
  const [isLoading, setIsLoading] = useState(true)

  useEffect(() => {
    // Check for existing session
    const storedUser = localStorage.getItem("user")
    if (storedUser) {
      setUser(JSON.parse(storedUser))
    }
    setIsLoading(false)
  }, [])

  const login = async (email: string, password: string) => {
    // Simulate login - in production, this would call your backend
    const users = JSON.parse(localStorage.getItem("users") || "[]")
    const foundUser = users.find((u: any) => u.email === email && u.password === password)

    if (!foundUser) {
      throw new Error("Invalid credentials")
    }

    if (foundUser.mfaEnabled) {
      // Store pending user for MFA verification
      sessionStorage.setItem("pendingUser", JSON.stringify(foundUser))
      return { requiresMFA: true }
    }

    const { password: _, ...userWithoutPassword } = foundUser
    setUser(userWithoutPassword)
    localStorage.setItem("user", JSON.stringify(userWithoutPassword))

    ActivityLogger.log(userWithoutPassword.id, userWithoutPassword.name, userWithoutPassword.email, "login", false)

    return { requiresMFA: false }
  }

  const verifyMFA = async (code: string) => {
    const pendingUser = sessionStorage.getItem("pendingUser")
    if (!pendingUser) return false

    // In production, verify the TOTP code against the user's secret
    // For demo, accept any 6-digit code
    if (code.length === 6) {
      const user = JSON.parse(pendingUser)
      const { password: _, ...userWithoutPassword } = user
      setUser(userWithoutPassword)
      localStorage.setItem("user", JSON.stringify(userWithoutPassword))
      sessionStorage.removeItem("pendingUser")

      ActivityLogger.log(
        userWithoutPassword.id,
        userWithoutPassword.name,
        userWithoutPassword.email,
        "mfa_verified",
        true,
      )
      ActivityLogger.log(userWithoutPassword.id, userWithoutPassword.name, userWithoutPassword.email, "login", true)

      return true
    }

    return false
  }

  const register = async (email: string, password: string, name: string) => {
    const users = JSON.parse(localStorage.getItem("users") || "[]")

    if (users.find((u: any) => u.email === email)) {
      throw new Error("User already exists")
    }

    const newUser = {
      id: crypto.randomUUID(),
      email,
      password,
      name,
      mfaEnabled: false,
      createdAt: new Date().toISOString(),
    }

    users.push(newUser)
    localStorage.setItem("users", JSON.stringify(users))

    const { password: _, ...userWithoutPassword } = newUser
    setUser(userWithoutPassword)
    localStorage.setItem("user", JSON.stringify(userWithoutPassword))

    ActivityLogger.log(userWithoutPassword.id, userWithoutPassword.name, userWithoutPassword.email, "login", false)
  }

  const enableMFA = async () => {
    if (!user) throw new Error("No user logged in")

    // Generate a secret (in production, use a proper TOTP library)
    const secret = crypto.randomUUID().replace(/-/g, "").substring(0, 32)

    const users = JSON.parse(localStorage.getItem("users") || "[]")
    const userIndex = users.findIndex((u: any) => u.id === user.id)

    if (userIndex !== -1) {
      users[userIndex].mfaEnabled = true
      users[userIndex].mfaSecret = secret
      localStorage.setItem("users", JSON.stringify(users))

      const updatedUser = { ...user, mfaEnabled: true, mfaSecret: secret }
      setUser(updatedUser)
      localStorage.setItem("user", JSON.stringify(updatedUser))

      ActivityLogger.log(user.id, user.name, user.email, "mfa_enabled", false)
    }

    return secret
  }

  const disableMFA = async () => {
    if (!user) throw new Error("No user logged in")

    const users = JSON.parse(localStorage.getItem("users") || "[]")
    const userIndex = users.findIndex((u: any) => u.id === user.id)

    if (userIndex !== -1) {
      users[userIndex].mfaEnabled = false
      delete users[userIndex].mfaSecret
      localStorage.setItem("users", JSON.stringify(users))

      const updatedUser = { ...user, mfaEnabled: false }
      delete updatedUser.mfaSecret
      setUser(updatedUser)
      localStorage.setItem("user", JSON.stringify(updatedUser))

      ActivityLogger.log(user.id, user.name, user.email, "mfa_disabled", false)
    }
  }

  const logout = () => {
    if (user) {
      ActivityLogger.log(user.id, user.name, user.email, "logout", false)
    }

    setUser(null)
    localStorage.removeItem("user")
    sessionStorage.removeItem("pendingUser")
  }

  return (
    <AuthContext.Provider
      value={{
        user,
        login,
        verifyMFA,
        logout,
        register,
        enableMFA,
        disableMFA,
        isLoading,
      }}
    >
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth() {
  const context = useContext(AuthContext)
  if (context === undefined) {
    throw new Error("useAuth must be used within an AuthProvider")
  }
  return context
}
