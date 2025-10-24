// Placeholder activity logger - to be implemented later
export class ActivityLogger {
  static log(userId: string, name: string, email: string, action: string, success: boolean) {
    console.log('Activity:', { userId, name, email, action, success })
  }

  static getLogsByUser(_userId: string) {
    return []
  }
}
