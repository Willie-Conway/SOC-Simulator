#!/bin/bash

echo "Ì∫Ä Deploying SOC Simulator to GitHub Pages via docs folder..."

# Build the app
npm run build

# Check if docs folder exists
if [ ! -d "docs" ]; then
    echo "‚ùå docs folder not created!"
    exit 1
fi

# Force add docs folder
git add -f docs/

# Commit
git commit -m "Update docs folder for GitHub Pages"

# Push
git push origin main

echo ""
echo "‚úÖ Deployment complete!"
echo "Ìºê Your site will be live at: https://willie-conway.github.io/soc-simulator"
echo "‚è≥ Wait 2-3 minutes for GitHub Pages to update"
