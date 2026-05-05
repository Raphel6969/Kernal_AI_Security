#!/bin/bash
# Setup Python backend environment
set -e

echo "🐍 Setting up Python backend environment..."

# Check Python version
python_version=$(python3 --version 2>&1 | awk '{print $2}')
echo "Using Python $python_version"

# Create virtual environment
echo "📦 Creating Python virtual environment..."
# BCC Python bindings are installed via apt (python3-bcc/python3-bpfcc), so
# we include system site-packages to make `from bcc import BPF` available.
python3 -m venv --system-site-packages venv
source venv/bin/activate

# Upgrade pip
echo "⬆️  Upgrading pip..."
pip install --upgrade pip setuptools wheel

# Install dependencies
echo "📦 Installing Python dependencies..."
cd backend
pip install -r requirements.txt

echo "✅ Backend setup complete!"
echo ""
echo "⚡ To activate the environment:"
echo "   source venv/bin/activate"
echo ""
echo "📝 Next steps:"
echo "   1. Activate: source venv/bin/activate"
echo "   2. Train model: python backend/models/train_model.py"
echo "   3. Run backend: python backend/app.py"
