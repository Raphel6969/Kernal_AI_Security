#!/bin/bash
# Setup React frontend environment
set -e

echo "⚛️  Setting up React frontend environment..."

# Check Node.js version
if ! command -v node &> /dev/null; then
    echo "❌ Node.js not installed. Please install Node.js 16+ first."
    echo "   Download: https://nodejs.org/"
    exit 1
fi

node_version=$(node --version)
echo "Using Node.js $node_version"

# Create React app with Vite
echo "📦 Creating React app with Vite..."
cd frontend

# Install dependencies
echo "📦 Installing npm dependencies..."
npm install

echo "✅ Frontend setup complete!"
echo ""
echo "⚡ To start development server:"
echo "   cd frontend && npm run dev"
echo ""
echo "📦 To build for production:"
echo "   npm run build"
