# Fix syntax errors in modern_ui_ultimate.py

# Read the file
with open('ui/modern_ui_ultimate.py', 'r') as f:
    content = f.read()

# Fix the syntax errors - remove ] after TEXT_BRIGHT
content = content.replace('TEXT_BRIGHT],', 'TEXT_BRIGHT,')

# Write back
with open('ui/modern_ui_ultimate.py', 'w') as f:
    f.write(content)

print('Fixed syntax errors!')
