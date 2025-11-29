#!/bin/bash

# Clerk Development Setup Script
# This script helps set up Clerk authentication for development

set -e

echo "🚀 Setting up Clerk authentication for development..."

# Check if .env exists
if [ ! -f ".env" ]; then
    echo "⚠️  .env file not found. Creating from .env.example..."
    cp .env.example .env
fi

# Check if Clerk keys are already set
if grep -q "CLERK_PUBLISHABLE_KEY=pk_test_" .env && grep -q "CLERK_SECRET_KEY=sk_test_" .env; then
    echo "✅ Clerk keys appear to be already configured."
else
    echo "⚠️  Clerk keys not found in .env file."
    echo ""
    echo "To complete the setup:"
    echo "1. Sign up at https://dashboard.clerk.com"
    echo "2. Create a new application"
    echo "3. Copy your Publishable and Secret keys"
    echo "4. Update the following variables in your .env file:"
    echo "   - CLERK_PUBLISHABLE_KEY=pk_test_..."
    echo "   - CLERK_SECRET_KEY=sk_test_..."
    echo "   - VITE_CLERK_PUBLISHABLE_KEY=pk_test_..."
    echo ""
fi

# Set registration to enabled for development
if ! grep -q "VITE_ENABLE_REGISTRATION" .env; then
    echo "VITE_ENABLE_REGISTRATION=true" >> .env
    echo "✅ Enabled registration for development"
fi

# Start the development environment
echo ""
echo "🔄 Starting development environment..."
echo ""
echo "Frontend will be available at: http://localhost:3000"
echo "Backend will be available at: http://localhost:8080"
echo ""
echo "To test Clerk authentication:"
echo "1. Navigate to http://localhost:3000/login"
echo "2. Click 'Sign Up' to create a new account"
echo "3. Or sign in with an existing account"
echo ""
echo "Press Ctrl+C to stop the development server"
echo ""

# Start the full stack
make up