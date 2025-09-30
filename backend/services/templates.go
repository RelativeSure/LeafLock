package services

import (
	"context"
	"fmt"
	"log"
)

// DefaultTemplate represents a default note template
type DefaultTemplate struct {
	Name        string
	Description string
	Content     string
	Tags        []string
	Icon        string
}

// defaultTemplates contains the default templates to seed into the database
var defaultTemplates = []DefaultTemplate{
	{
		Name:        "Meeting Notes",
		Description: "Template for recording meeting discussions and action items",
		Content: `# Meeting Notes

**Date:** ${date}
**Attendees:**
**Duration:**

## Agenda
1.
2.
3.

## Discussion Points
### Topic 1
-
-

### Topic 2
-
-

## Action Items
- [ ] Task 1 - Assigned to: ${person} - Due: ${date}
- [ ] Task 2 - Assigned to: ${person} - Due: ${date}

## Next Meeting
**Date:**
**Topics to discuss:**
-
- `,
		Tags: []string{"meeting", "work", "action-items"},
		Icon: "📝",
	},
	{
		Name:        "Project Planning",
		Description: "Template for planning projects with goals, milestones, and resources",
		Content: `# Project: ${project_name}

## Overview
**Start Date:** ${date}
**End Date:** ${date}
**Project Manager:** ${person}
**Budget:** $

## Goals & Objectives
### Primary Goal
-

### Secondary Goals
-
-

## Project Scope
### Included
-
-

### Excluded
-
-

## Timeline & Milestones
- [ ] **Phase 1:** ${milestone} - Due: ${date}
- [ ] **Phase 2:** ${milestone} - Due: ${date}
- [ ] **Phase 3:** ${milestone} - Due: ${date}

## Resources Required
### Team Members
- ${person} - Role:
- ${person} - Role:

### Tools & Technology
-
-

### Budget Breakdown
- Category 1: $
- Category 2: $
- Total: $

## Risk Assessment
### High Priority Risks
- **Risk:** ${risk} - **Mitigation:** ${strategy}

### Medium Priority Risks
- **Risk:** ${risk} - **Mitigation:** ${strategy}

## Success Criteria
-
-
- `,
		Tags: []string{"project", "planning", "work", "goals"},
		Icon: "📊",
	},
	{
		Name:        "Daily Journal",
		Description: "Template for daily reflection and gratitude practice",
		Content: `# Daily Journal - ${date}

## Today's Mood
Scale 1-10: ___
Overall feeling:

## Gratitude
3 things I'm grateful for today:
1.
2.
3.

## Today's Priorities
### Must Do
- [ ]
- [ ]
- [ ]

### Should Do
- [ ]
- [ ]

### Could Do
- [ ]
- [ ]

## Reflections
### What went well today?
-
-

### What could have been better?
-
-

### What did I learn?
-
-

## Tomorrow's Focus
Main priority:
3 key tasks:
1.
2.
3.

## Random Thoughts
${thoughts}

---
*"Every day is a new beginning."*`,
		Tags: []string{"journal", "personal", "gratitude", "reflection"},
		Icon: "🗒️",
	},
	{
		Name:        "Code Review Checklist",
		Description: "Template for thorough code review documentation",
		Content: `# Code Review: ${feature_name}

**Pull Request:** #${pr_number}
**Author:** ${developer}
**Reviewer:** ${reviewer}
**Date:** ${date}

## Summary
Brief description of changes:


## Review Checklist

### Code Quality
- [ ] Code follows project style guidelines
- [ ] Functions are well-named and focused
- [ ] Code is DRY (Don't Repeat Yourself)
- [ ] Comments explain the "why", not the "what"
- [ ] No commented-out code left behind

### Functionality
- [ ] Code does what it's supposed to do
- [ ] Edge cases are handled
- [ ] Error handling is appropriate
- [ ] Input validation is present where needed

### Performance
- [ ] No obvious performance issues
- [ ] Database queries are optimized
- [ ] Caching used where appropriate
- [ ] No memory leaks

### Security
- [ ] No hardcoded secrets
- [ ] Input sanitization implemented
- [ ] Authorization checks in place
- [ ] HTTPS used for sensitive data

### Testing
- [ ] Unit tests cover new functionality
- [ ] Integration tests updated if needed
- [ ] Test coverage is adequate
- [ ] Tests are meaningful and not just for coverage

## Detailed Comments

### Positive Feedback
-
-

### Issues Found
1. **File:** ${file} **Line:** ${line}
   **Issue:**
   **Suggestion:**

2. **File:** ${file} **Line:** ${line}
   **Issue:**
   **Suggestion:**

## Overall Assessment
- [ ] Approve
- [ ] Approve with minor changes
- [ ] Request changes
- [ ] Major revision needed

**Final Comments:**


**Next Steps:**
- `,
		Tags: []string{"code-review", "development", "quality", "checklist"},
		Icon: "🔍",
	},
	{
		Name:        "Bug Report",
		Description: "Template for documenting software bugs with all necessary details",
		Content: `# Bug Report: ${bug_title}

**Reporter:** ${person}
**Date:** ${date}
**Priority:** [ ] Low [ ] Medium [ ] High [ ] Critical
**Status:** Open

## Environment
- **OS:**
- **Browser/App Version:**
- **Device:**
- **Screen Resolution:**

## Description
Brief summary of the issue:


## Steps to Reproduce
1.
2.
3.
4.

## Expected Behavior
What should happen:


## Actual Behavior
What actually happens:


## Screenshots/Videos
[Attach screenshots or screen recordings if applicable]

## Error Messages
` + "```" + `
[Paste any error messages here]
` + "```" + `

## Console Logs
` + "```" + `
[Paste relevant console logs here]
` + "```" + `

## Additional Context
Any other information that might be helpful:


## Workaround
Temporary solution (if any):


## Related Issues
- Issue #
- Related to:

---

## For Developers

### Investigation Notes
-

### Root Cause
-

### Proposed Solution
-

### Testing Requirements
- [ ] Unit tests
- [ ] Integration tests
- [ ] Manual testing scenarios:
  -
  -

### Deployment Notes
- `,
		Tags: []string{"bug-report", "development", "testing", "issue"},
		Icon: "🐛",
	},
}

// SeedDefaultTemplates creates default public templates if they don't exist
func SeedDefaultTemplates(db Database, crypto CryptoService) error {
	ctx := context.Background()

	// Check if we already have default templates
	var count int
	err := db.QueryRow(ctx, `SELECT COUNT(*) FROM templates WHERE tags @> ARRAY['system']`).Scan(&count)
	if err != nil {
		return fmt.Errorf("failed to check existing templates: %w", err)
	}

	if count > 0 {
		log.Println("Default templates already exist, skipping seed")
		return nil
	}

	log.Println("Seeding default templates...")

	for _, template := range defaultTemplates {
		// Encrypt template data (Encrypt returns []byte)
		nameEncryptedBytes, err := crypto.Encrypt([]byte(template.Name))
		if err != nil {
			return fmt.Errorf("failed to encrypt template name '%s': %w", template.Name, err)
		}

		descriptionEncryptedBytes, err := crypto.Encrypt([]byte(template.Description))
		if err != nil {
			return fmt.Errorf("failed to encrypt template description '%s': %w", template.Name, err)
		}

		contentEncryptedBytes, err := crypto.Encrypt([]byte(template.Content))
		if err != nil {
			return fmt.Errorf("failed to encrypt template content '%s': %w", template.Name, err)
		}

		// Add 'system' tag to identify default templates
		tags := append(template.Tags, "system")

		// Insert template
		_, err = db.Exec(ctx, `
			INSERT INTO templates (user_id, name_encrypted, description_encrypted, content_encrypted, tags, icon, is_public, usage_count)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		`, nil, nameEncryptedBytes, descriptionEncryptedBytes, contentEncryptedBytes, tags, template.Icon, true, 0)
		if err != nil {
			return fmt.Errorf("failed to insert template '%s': %w", template.Name, err)
		}

		log.Printf("✅ Created default template: %s", template.Name)
	}

	log.Printf("Successfully seeded %d default templates", len(defaultTemplates))
	return nil
}