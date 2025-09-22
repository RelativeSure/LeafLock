#!/usr/bin/env node

import fs from 'fs/promises'
import path from 'path'

const sourceDir = '../docs'
const targetDir = 'content'

async function migrateContent() {
  console.log('🚀 Starting migration from Hugo to ElysiaJS...')
  
  // Create content directory
  try {
    await fs.mkdir(targetDir, { recursive: true })
  } catch (err) {
    // Directory might already exist
  }
  
  // Copy the main index file
  console.log('📄 Copying index file...')
  try {
    const indexContent = await fs.readFile('../docs/site/content/_index.md', 'utf-8')
    await fs.writeFile(path.join(targetDir, 'index.md'), indexContent)
    console.log('✅ Index file copied')
  } catch (err) {
    console.error('❌ Error copying index file:', err.message)
  }
  
  // List of files to migrate
  const files = [
    'admin-guide.md',
    'developer-guide.md', 
    'gdpr-compliance.md',
    'gdpr-operations-guide.md',
    'global-compliance.md',
    'license.md',
    'monitoring-and-backups.md',
    'privacy-policy.md',
    'terms-of-use.md'
  ]
  
  console.log('📁 Copying documentation files...')
  
  for (const file of files) {
    try {
      const content = await fs.readFile(path.join(sourceDir, file), 'utf-8')
      await fs.writeFile(path.join(targetDir, file), content)
      console.log(`✅ ${file} copied`)
    } catch (err) {
      console.error(`❌ Error copying ${file}:`, err.message)
    }
  }
  
  console.log('🎉 Migration completed!')
  console.log('📂 All content is now available in the content/ directory')
  console.log('🚀 You can now run: bun run dev')
}

migrateContent().catch(console.error)