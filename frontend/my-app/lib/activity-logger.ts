import type { UserActivityLog } from "./types"

export class ActivityLogger {
  private static STORAGE_KEY = "user_activity_logs"
  private static RETENTION_DAYS = 90

  static log(
    userId: string,
    userName: string,
    userEmail: string,
    action: UserActivityLog["action"],
    mfaUsed = false,
  ): void {
    const logs = this.getLogs()

    const newLog: UserActivityLog = {
      id: crypto.randomUUID(),
      userId,
      userName,
      userEmail,
      action,
      timestamp: new Date().toISOString(),
      ipAddress: "127.0.0.1", // In production, get real IP
      userAgent: navigator.userAgent,
      mfaUsed,
    }

    logs.unshift(newLog)

    const retentionDate = new Date()
    retentionDate.setDate(retentionDate.getDate() - this.RETENTION_DAYS)
    const filteredLogs = logs.filter((log) => new Date(log.timestamp) > retentionDate)

    // Keep only last 1000 logs
    if (filteredLogs.length > 1000) {
      filteredLogs.splice(1000)
    }

    localStorage.setItem(this.STORAGE_KEY, JSON.stringify(filteredLogs))
  }

  static getLogs(): UserActivityLog[] {
    const logs = localStorage.getItem(this.STORAGE_KEY)
    if (!logs) return []

    const parsedLogs = JSON.parse(logs)
    const retentionDate = new Date()
    retentionDate.setDate(retentionDate.getDate() - this.RETENTION_DAYS)

    return parsedLogs.filter((log: UserActivityLog) => new Date(log.timestamp) > retentionDate)
  }

  static getLogsByUser(userId: string): UserActivityLog[] {
    return this.getLogs().filter((log) => log.userId === userId)
  }

  static clearLogs(): void {
    localStorage.removeItem(this.STORAGE_KEY)
  }

  static getRetentionInfo() {
    return {
      retentionDays: this.RETENTION_DAYS,
      retentionPolicy: `Activity logs are automatically deleted after ${this.RETENTION_DAYS} days`,
    }
  }

  static exportUserData(userId: string) {
    const logs = this.getLogsByUser(userId)
    return {
      activityLogs: logs,
      totalLogs: logs.length,
      oldestLog: logs.length > 0 ? logs[logs.length - 1].timestamp : null,
      newestLog: logs.length > 0 ? logs[0].timestamp : null,
      retentionPolicy: this.getRetentionInfo(),
    }
  }
}
