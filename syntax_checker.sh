#!/bin/bash
# Bash Script Syntax Checker
# ตรวจสอบ syntax errors ใน bash script

SCRIPT_FILE="$1"

if [ -z "$SCRIPT_FILE" ]; then
    echo "Usage: $0 <script_file>"
    exit 1
fi

if [ ! -f "$SCRIPT_FILE" ]; then
    echo "Error: File '$SCRIPT_FILE' not found"
    exit 1
fi

echo "==================================="
echo "Bash Script Syntax Checker"
echo "==================================="
echo "Checking: $SCRIPT_FILE"
echo

# 1. Check basic syntax with bash -n
echo "1. Basic syntax check..."
if bash -n "$SCRIPT_FILE" 2>/tmp/syntax_errors.log; then
    echo "   ✓ Basic syntax OK"
else
    echo "   ✗ Syntax errors found:"
    cat /tmp/syntax_errors.log | sed 's/^/     /'
    echo
fi

# 2. Check for balanced quotes
echo "2. Checking for balanced quotes..."
SINGLE_QUOTES=$(grep -o "'" "$SCRIPT_FILE" | wc -l)
DOUBLE_QUOTES=$(grep -o '"' "$SCRIPT_FILE" | wc -l)

if [ $((SINGLE_QUOTES % 2)) -eq 0 ]; then
    echo "   ✓ Single quotes balanced ($SINGLE_QUOTES)"
else
    echo "   ✗ Single quotes unbalanced ($SINGLE_QUOTES)"
fi

if [ $((DOUBLE_QUOTES % 2)) -eq 0 ]; then
    echo "   ✓ Double quotes balanced ($DOUBLE_QUOTES)"
else
    echo "   ✗ Double quotes unbalanced ($DOUBLE_QUOTES)"
fi

# 3. Check for common missing closures
echo "3. Checking for common missing closures..."

# Check if/fi pairs
IF_COUNT=$(grep -c "^[[:space:]]*if\|[[:space:]]if[[:space:]]" "$SCRIPT_FILE")
FI_COUNT=$(grep -c "^[[:space:]]*fi[[:space:]]*$\|[[:space:]]fi[[:space:]]*$" "$SCRIPT_FILE")
echo "   if statements: $IF_COUNT, fi statements: $FI_COUNT"
if [ "$IF_COUNT" -eq "$FI_COUNT" ]; then
    echo "   ✓ if/fi pairs balanced"
else
    echo "   ✗ if/fi pairs unbalanced"
fi

# Check for/done pairs
FOR_COUNT=$(grep -c "^[[:space:]]*for\|[[:space:]]for[[:space:]]" "$SCRIPT_FILE")
WHILE_COUNT=$(grep -c "^[[:space:]]*while\|[[:space:]]while[[:space:]]" "$SCRIPT_FILE")
DONE_COUNT=$(grep -c "^[[:space:]]*done[[:space:]]*$\|[[:space:]]done[[:space:]]*$" "$SCRIPT_FILE")
LOOP_COUNT=$((FOR_COUNT + WHILE_COUNT))
echo "   loops (for+while): $LOOP_COUNT, done statements: $DONE_COUNT"
if [ "$LOOP_COUNT" -eq "$DONE_COUNT" ]; then
    echo "   ✓ loop/done pairs balanced"
else
    echo "   ✗ loop/done pairs unbalanced"
fi

# Check function braces
FUNCTION_OPEN=$(grep -c "{" "$SCRIPT_FILE")
FUNCTION_CLOSE=$(grep -c "}" "$SCRIPT_FILE")
echo "   opening braces: $FUNCTION_OPEN, closing braces: $FUNCTION_CLOSE"
if [ "$FUNCTION_OPEN" -eq "$FUNCTION_CLOSE" ]; then
    echo "   ✓ braces balanced"
else
    echo "   ✗ braces unbalanced"
fi

# 4. Check for proper heredoc syntax
echo "4. Checking heredoc syntax..."
HEREDOC_ERRORS=$(grep -n "<<.*EOF" "$SCRIPT_FILE" | while read line; do
    LINE_NUM=$(echo "$line" | cut -d: -f1)
    EOF_MARKER=$(echo "$line" | sed 's/.*<<[[:space:]]*\([A-Z_]*\).*/\1/')
    
    # Check if corresponding EOF exists
    if ! tail -n +$((LINE_NUM + 1)) "$SCRIPT_FILE" | grep -q "^$EOF_MARKER$"; then
        echo "   ✗ Line $LINE_NUM: Missing closing $EOF_MARKER"
        return 1
    fi
done)

if [ -z "$HEREDOC_ERRORS" ]; then
    echo "   ✓ Heredoc syntax OK"
else
    echo "$HEREDOC_ERRORS"
fi

# 5. Check line endings
echo "5. Checking line endings..."
if file "$SCRIPT_FILE" | grep -q "CRLF"; then
    echo "   ✗ Windows line endings detected (CRLF)"
    echo "   Run: dos2unix $SCRIPT_FILE"
else
    echo "   ✓ Unix line endings (LF)"
fi

# 6. Check for proper script termination
echo "6. Checking script termination..."
LAST_LINE=$(tail -n 1 "$SCRIPT_FILE" | sed 's/[[:space:]]*$//')
if [ "$LAST_LINE" = "exit 0" ] || [ "$LAST_LINE" = "exit 1" ]; then
    echo "   ✓ Script has proper exit statement"
else
    echo "   ⚠ Script should end with 'exit 0' or 'exit 1'"
fi

echo
echo "==================================="
echo "Syntax check completed"
echo "==================================="

# Clean up
rm -f /tmp/syntax_errors.log
