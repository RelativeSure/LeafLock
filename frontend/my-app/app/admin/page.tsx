"use client"

import { useEffect, useState } from "react"
import { useRouter } from "next/navigation"
import { useAuth } from "@/lib/auth-context"
import { ActivityLogger } from "@/lib/activity-logger"
import type { UserActivityLog } from "@/lib/types"
import { ThemeToggle } from "@/components/theme-toggle"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Shield, ArrowLeft, Search, Download, Trash2, CheckCircle2, XCircle, ShieldIcon } from "lucide-react"
import { Card } from "@/components/ui/card"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Badge } from "@/components/ui/badge"
import { ScrollArea } from "@/components/ui/scroll-area"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"

export default function AdminPage() {
  const { user, isLoading } = useAuth()
  const router = useRouter()
  const [logs, setLogs] = useState<UserActivityLog[]>([])
  const [searchQuery, setSearchQuery] = useState("")
  const [filterAction, setFilterAction] = useState<string>("all")

  useEffect(() => {
    if (!isLoading && !user) {
      router.push("/auth")
    }
  }, [user, isLoading, router])

  useEffect(() => {
    if (user) {
      setLogs(ActivityLogger.getLogs())
    }
  }, [user])

  if (isLoading || !user) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
      </div>
    )
  }

  const filteredLogs = logs.filter((log) => {
    const matchesSearch =
      log.userName.toLowerCase().includes(searchQuery.toLowerCase()) ||
      log.userEmail.toLowerCase().includes(searchQuery.toLowerCase()) ||
      log.action.toLowerCase().includes(searchQuery.toLowerCase())

    const matchesFilter = filterAction === "all" || log.action === filterAction

    return matchesSearch && matchesFilter
  })

  const getActionBadge = (action: UserActivityLog["action"]) => {
    const variants: Record<string, { variant: any; label: string }> = {
      login: { variant: "default", label: "Login" },
      logout: { variant: "secondary", label: "Logout" },
      mfa_enabled: { variant: "default", label: "MFA Enabled" },
      mfa_disabled: { variant: "destructive", label: "MFA Disabled" },
      mfa_verified: { variant: "default", label: "MFA Verified" },
    }

    const config = variants[action] || { variant: "secondary", label: action }
    return <Badge variant={config.variant}>{config.label}</Badge>
  }

  const exportLogs = () => {
    const csv = [
      ["Timestamp", "User", "Email", "Action", "MFA Used", "IP Address", "User Agent"].join(","),
      ...filteredLogs.map((log) =>
        [
          log.timestamp,
          log.userName,
          log.userEmail,
          log.action,
          log.mfaUsed ? "Yes" : "No",
          log.ipAddress || "",
          `"${log.userAgent || ""}"`,
        ].join(","),
      ),
    ].join("\n")

    const blob = new Blob([csv], { type: "text/csv" })
    const url = URL.createObjectURL(blob)
    const a = document.createElement("a")
    a.href = url
    a.download = `activity-logs-${new Date().toISOString()}.csv`
    a.click()
  }

  const clearAllLogs = () => {
    if (confirm("Are you sure you want to clear all activity logs?")) {
      ActivityLogger.clearLogs()
      setLogs([])
    }
  }

  const stats = {
    totalLogins: logs.filter((l) => l.action === "login").length,
    mfaLogins: logs.filter((l) => l.action === "login" && l.mfaUsed).length,
    uniqueUsers: new Set(logs.map((l) => l.userId)).size,
    recentActivity: logs.filter((l) => new Date(l.timestamp) > new Date(Date.now() - 24 * 60 * 60 * 1000)).length,
  }

  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <header className="border-b border-border bg-card px-6 py-3 flex items-center justify-between animate-slide-in">
        <div className="flex items-center gap-3">
          <Button variant="ghost" size="sm" onClick={() => router.push("/dashboard")}>
            <ArrowLeft className="h-4 w-4 mr-2" />
            Back
          </Button>
          <div className="w-8 h-8 rounded-lg bg-primary flex items-center justify-center">
            <Shield className="w-5 h-5 text-primary-foreground" />
          </div>
          <h1 className="text-xl font-bold">Admin Dashboard</h1>
        </div>

        <ThemeToggle />
      </header>

      <div className="p-8">
        <div className="max-w-7xl mx-auto space-y-6">
          {/* Stats Cards */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4 animate-in fade-in-50 duration-500">
            <Card className="p-6 hover-lift transition-smooth">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-muted-foreground">Total Logins</p>
                  <p className="text-2xl font-bold mt-1">{stats.totalLogins}</p>
                </div>
                <div className="w-12 h-12 rounded-full bg-primary/10 flex items-center justify-center">
                  <CheckCircle2 className="h-6 w-6 text-primary" />
                </div>
              </div>
            </Card>

            <Card className="p-6 hover-lift transition-smooth">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-muted-foreground">MFA Logins</p>
                  <p className="text-2xl font-bold mt-1">{stats.mfaLogins}</p>
                </div>
                <div className="w-12 h-12 rounded-full bg-accent/10 flex items-center justify-center">
                  <ShieldIcon className="h-6 w-6 text-accent" />
                </div>
              </div>
            </Card>

            <Card className="p-6 hover-lift transition-smooth">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-muted-foreground">Unique Users</p>
                  <p className="text-2xl font-bold mt-1">{stats.uniqueUsers}</p>
                </div>
                <div className="w-12 h-12 rounded-full bg-secondary/10 flex items-center justify-center">
                  <Shield className="h-6 w-6 text-secondary-foreground" />
                </div>
              </div>
            </Card>

            <Card className="p-6 hover-lift transition-smooth">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-muted-foreground">Last 24h Activity</p>
                  <p className="text-2xl font-bold mt-1">{stats.recentActivity}</p>
                </div>
                <div className="w-12 h-12 rounded-full bg-primary/10 flex items-center justify-center">
                  <CheckCircle2 className="h-6 w-6 text-primary" />
                </div>
              </div>
            </Card>
          </div>

          {/* Filters and Actions */}
          <Card className="p-6 animate-in fade-in-50 duration-700">
            <div className="flex flex-col md:flex-row gap-4 items-start md:items-center justify-between">
              <div className="flex-1 flex gap-3 w-full md:w-auto">
                <div className="relative flex-1">
                  <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                  <Input
                    placeholder="Search by user, email, or action..."
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    className="pl-10"
                  />
                </div>
                <Select value={filterAction} onValueChange={setFilterAction}>
                  <SelectTrigger className="w-[180px]">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All Actions</SelectItem>
                    <SelectItem value="login">Login</SelectItem>
                    <SelectItem value="logout">Logout</SelectItem>
                    <SelectItem value="mfa_enabled">MFA Enabled</SelectItem>
                    <SelectItem value="mfa_disabled">MFA Disabled</SelectItem>
                    <SelectItem value="mfa_verified">MFA Verified</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              <div className="flex gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={exportLogs}
                  className="transition-smooth hover-lift bg-transparent"
                >
                  <Download className="h-4 w-4 mr-2" />
                  Export CSV
                </Button>
                <Button variant="destructive" size="sm" onClick={clearAllLogs} className="transition-smooth">
                  <Trash2 className="h-4 w-4 mr-2" />
                  Clear Logs
                </Button>
              </div>
            </div>
          </Card>

          {/* Activity Logs Table */}
          <Card className="animate-in fade-in-50 duration-1000">
            <ScrollArea className="h-[600px]">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Timestamp</TableHead>
                    <TableHead>User</TableHead>
                    <TableHead>Email</TableHead>
                    <TableHead>Action</TableHead>
                    <TableHead>MFA Used</TableHead>
                    <TableHead>IP Address</TableHead>
                    <TableHead className="w-[200px]">User Agent</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filteredLogs.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={7} className="text-center py-8 text-muted-foreground">
                        No activity logs found
                      </TableCell>
                    </TableRow>
                  ) : (
                    filteredLogs.map((log) => (
                      <TableRow key={log.id} className="transition-smooth hover:bg-muted/50">
                        <TableCell className="font-mono text-xs">{new Date(log.timestamp).toLocaleString()}</TableCell>
                        <TableCell className="font-medium">{log.userName}</TableCell>
                        <TableCell className="text-sm text-muted-foreground">{log.userEmail}</TableCell>
                        <TableCell>{getActionBadge(log.action)}</TableCell>
                        <TableCell>
                          {log.mfaUsed ? (
                            <CheckCircle2 className="h-4 w-4 text-green-500" />
                          ) : (
                            <XCircle className="h-4 w-4 text-muted-foreground" />
                          )}
                        </TableCell>
                        <TableCell className="font-mono text-xs">{log.ipAddress}</TableCell>
                        <TableCell className="text-xs text-muted-foreground truncate max-w-[200px]">
                          {log.userAgent}
                        </TableCell>
                      </TableRow>
                    ))
                  )}
                </TableBody>
              </Table>
            </ScrollArea>
          </Card>
        </div>
      </div>
    </div>
  )
}
