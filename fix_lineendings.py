with open('scripts/demo.sh', 'rb') as f:
    content = f.read()

with open('scripts/demo.sh', 'wb') as f:
    f.write(content.replace(b'\r\n', b'\n'))

print("✓ Converted line endings from CRLF to LF")
