import React from 'react'
import SettingsPage from '@/features/settings/components/SettingsPage'
import { secureApi as api } from '@/services/api/secureApi'

interface SettingsViewProps {
  onBack: () => void
  onLogout: () => void
}

export const SettingsView: React.FC<SettingsViewProps> = ({ onBack, onLogout }) => {
  return <SettingsPage api={api} onBack={onBack} onLogout={onLogout} />
}

export default SettingsView
