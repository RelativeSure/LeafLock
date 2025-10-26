// Placeholder collaboration context - to be implemented later
interface User {
  id: string
  name: string
  email: string
  color: string
}

export function useCollaboration() {
  return {
    getSessionUsers: (_noteId: string): User[] => [],
    joinSession: (_noteId: string) => {
      // TODO: Implement collaboration session joining
      // Don't log - collaboration is controlled by Share button only
    },
    leaveSession: (_noteId: string) => {
      // TODO: Implement collaboration session leaving
      // Don't log - collaboration is controlled by Share button only
    },
    shareNote: (_noteId: string, _email: string) => Promise.resolve(),
    unshareNote: (_noteId: string, _userId: string) => Promise.resolve(),
    getSharedUsers: (_noteId: string): User[] => [],
  }
}
