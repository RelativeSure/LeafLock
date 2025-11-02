#!/usr/bin/env python3
"""
Fix all remaining TypeScript test errors
"""
import re
from pathlib import Path

FRONTEND_DIR = Path(__file__).parent

def add_created_at_to_user(content: str) -> str:
    """Add createdAt to User mock objects"""
    # Pattern: User object with email, name, role, etc but no createdAt
    pattern = r'(\{[^}]*id:\s*[\'"][^\'"]+[\'"][^}]*email:[^}]*mfaEnabled:[^}]*)(})'
    
    def replacer(match):
        obj = match.group(1)
        if 'createdAt' not in obj:
            return obj + ", createdAt: '2024-01-01' }"
        return match.group(0)
    
    return re.sub(pattern, replacer, content)

def fix_encryption_version(content: str) -> str:
    """Fix encryptionVersion from 'v1' to 1"""
    content = re.sub(r"encryptionVersion:\s*['\"]v1['\"]", "encryptionVersion: 1", content)
    return content

def add_missing_note_fields(content: str) -> str:
    """Add createdAt to Note objects if missing"""
    # After updatedAt, check if there's createdAt before it
    lines = content.split('\n')
    new_lines = []
    
    for i, line in enumerate(lines):
        if 'updatedAt:' in line and i > 0:
            # Check if createdAt exists in previous 10 lines
            has_created = any('createdAt:' in lines[max(0, i-10):i][j] for j in range(len(lines[max(0, i-10):i])))
            if not has_created:
                # Add createdAt before updatedAt
                indent = len(line) - len(line.lstrip())
                new_lines.append(' ' * indent + "createdAt: '2024-01-01',")
        new_lines.append(line)
    
    return '\n'.join(new_lines)

def fix_note_version_missing_created_at(content: str) -> str:
    """Add createdAt to NoteVersion objects"""
    # Pattern: NoteVersion with createdBy but no createdAt after
    pattern = r'(createdBy:\s*[\'"][^\'"]+[\'"],?\s*)(\})'
    
    def replacer(match):
        return match.group(1) + ", createdAt: '2024-01-01' }"
    
    return re.sub(pattern, replacer, content)

def add_color_to_tag(content: str) -> str:
    """Add missing color field to Tag objects"""
    # Pattern: Tag with id, name, userId but no color
    pattern = r'(\{[^}]*id:\s*[\'"][^\'"]+[\'"][^}]*name:\s*[\'"][^\'"]+[\'"][^}]*userId:[^}]*)(})'
    
    def replacer(match):
        obj = match.group(1)
        if 'color' not in obj:
            return obj + ", color: '#000000' }"
        return match.group(0)
    
    return re.sub(pattern, replacer, content)

def add_tags_to_template(content: str) -> str:
    """Add missing tags array to Template objects"""
    # Pattern: Template with name, content but no tags
    pattern = r'(\{[^}]*name:\s*[\'"][^\'"]+[\'"][^}]*content:[^}]*)(})'
    
    def replacer(match):
        obj = match.group(1)
        if 'tags:' not in obj and ('isPublic' in obj or 'usageCount' in obj or 'Template' in obj):
            return obj + ", tags: [] }"
        return match.group(0)
    
    return re.sub(pattern, replacer, content)

def fix_enable_mfa_calls(content: str) -> str:
    """Remove arguments from enableMFA() calls"""
    content = re.sub(r"\.enableMFA\(['\"][^'\"]*['\"]\)", ".enableMFA()", content)
    return content

def process_file(filepath: Path) -> bool:
    """Process a single file"""
    try:
        content = filepath.read_text()
        original = content
        
        # Apply all fixes
        content = add_created_at_to_user(content)
        content = fix_encryption_version(content)
        content = add_missing_note_fields(content)
        content = fix_note_version_missing_created_at(content)
        content = add_color_to_tag(content)
        content = add_tags_to_template(content)
        content = fix_enable_mfa_calls(content)
        
        if content != original:
            filepath.write_text(content)
            print(f"✓ {filepath.relative_to(FRONTEND_DIR)}")
            return True
        return False
    except Exception as e:
        print(f"✗ {filepath}: {e}")
        return False

def main():
    test_files = list(FRONTEND_DIR.glob('src/**/*.test.ts*'))
    print(f"Processing {len(test_files)} test files...")
    
    fixed = sum(process_file(f) for f in test_files)
    print(f"\nFixed {fixed} files")

if __name__ == '__main__':
    main()
