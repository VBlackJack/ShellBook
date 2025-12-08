---
title: "Sed & Awk Cheatsheet"
description: "Essential text processing one-liners for sed and awk"
tags: ["sed", "awk", "linux", "text-processing", "cheatsheet"]
---

# Sed & Awk Cheatsheet

## Sed Basics

### Syntax

```bash
sed [options] 'command' file
sed [options] -e 'command1' -e 'command2' file
sed [options] -f script.sed file
```

### Common Options

| Option | Description |
|--------|-------------|
| `-i` | Edit file in-place |
| `-i.bak` | Edit in-place with backup |
| `-n` | Suppress automatic output |
| `-e` | Multiple commands |
| `-f` | Read commands from file |
| `-r` or `-E` | Extended regex |

## Sed Commands

### Substitution

```bash
# Basic substitution (first occurrence)
sed 's/old/new/' file

# Global substitution (all occurrences)
sed 's/old/new/g' file

# Case-insensitive substitution
sed 's/old/new/gi' file

# Substitute on specific line
sed '3 s/old/new/' file

# Substitute on range
sed '1,5 s/old/new/g' file

# Substitute from line to end
sed '10,$ s/old/new/g' file

# Print only changed lines
sed -n 's/old/new/gp' file

# Write changes to file
sed -i 's/old/new/g' file

# With backup
sed -i.bak 's/old/new/g' file
```

### Delete

```bash
# Delete line 3
sed '3d' file

# Delete lines 1-5
sed '1,5d' file

# Delete last line
sed '$d' file

# Delete blank lines
sed '/^$/d' file

# Delete lines matching pattern
sed '/pattern/d' file

# Delete lines NOT matching pattern
sed '/pattern/!d' file

# Delete lines starting with #
sed '/^#/d' file

# Delete trailing whitespace
sed 's/[[:space:]]*$//' file
```

### Print

```bash
# Print line 3
sed -n '3p' file

# Print lines 1-5
sed -n '1,5p' file

# Print lines matching pattern
sed -n '/pattern/p' file

# Print lines NOT matching pattern
sed -n '/pattern/!p' file

# Print and delete (move to end)
sed -n '/pattern/{p;d;}' file

# Print line number
sed -n '/pattern/=' file

# Print with line numbers
sed = file | sed 'N;s/\n/\t/'
```

### Insert & Append

```bash
# Insert before line 3
sed '3i\New line' file

# Append after line 3
sed '3a\New line' file

# Insert before matching pattern
sed '/pattern/i\New line' file

# Append after matching pattern
sed '/pattern/a\New line' file

# Insert at beginning
sed '1i\Header line' file

# Append at end
sed '$a\Footer line' file
```

### Change

```bash
# Replace line 3
sed '3c\New content' file

# Replace lines 1-5
sed '1,5c\New content' file

# Replace matching lines
sed '/pattern/c\New content' file
```

## Sed Advanced Patterns

### Address Ranges

```bash
# Lines 10 to 20
sed -n '10,20p' file

# Line 5 to end
sed -n '5,$p' file

# First occurrence of pattern to line 50
sed -n '/start/,50p' file

# Between two patterns
sed -n '/start/,/end/p' file

# From pattern to 5 lines after
sed -n '/pattern/,+5p' file

# Every 2nd line
sed -n '1~2p' file

# Every 5th line starting from line 10
sed -n '10~5p' file
```

### Multiple Commands

```bash
# Multiple substitutions
sed -e 's/foo/bar/g' -e 's/hello/world/g' file

# Alternative syntax
sed 's/foo/bar/g; s/hello/world/g' file

# From script file
cat script.sed
s/foo/bar/g
s/hello/world/g

sed -f script.sed file

# Pipe commands
sed '1,10d' file | sed 's/old/new/g'
```

### Backreferences

```bash
# Capture groups
sed 's/\(.*\)@\(.*\)/\2@\1/' file

# Swap two words
sed 's/\(word1\) \(word2\)/\2 \1/' file

# Extract domain from email
sed 's/.*@\(.*\)/\1/' emails.txt

# Add quotes around words
sed 's/\([a-z]*\)/"\1"/g' file

# Duplicate each line
sed 'p' file

# Duplicate and modify
sed 'p; s/foo/bar/' file
```

### Hold Space

```bash
# Reverse lines (tac alternative)
sed '1!G;h;$!d' file

# Remove duplicate consecutive lines
sed '$!N; /^\(.*\)\n\1$/!P; D' file

# Print every other line (odd lines)
sed -n '1~2p' file

# Print every other line (even lines)
sed -n '2~2p' file

# Join every two lines
sed 'N;s/\n/ /' file
```

## Sed One-Liners

### Text Manipulation

```bash
# Double space a file
sed G file

# Remove double spacing
sed 'n;d' file

# Number non-blank lines
sed '/./=' file | sed 'N;s/\n/ /'

# Center text (assuming 80 columns)
sed 's/^/                                       /;s/^\(.\{40\}\).*/\1/' file

# Right-align text (80 columns)
sed 's/^/                                                                                /;s/^\(.*\).\{80\}/\1/' file

# Convert DOS to Unix (remove CR)
sed 's/\r$//' file

# Convert Unix to DOS (add CR)
sed 's/$/\r/' file

# Remove HTML tags
sed 's/<[^>]*>//g' file

# Extract emails
sed -n '/[a-zA-Z0-9._%+-]*@[a-zA-Z0-9.-]*\.[a-zA-Z]\{2,\}/p' file
```

### Common Tasks

```bash
# Replace multiple spaces with single space
sed 's/  */ /g' file

# Remove leading spaces
sed 's/^[ \t]*//' file

# Remove trailing spaces
sed 's/[ \t]*$//' file

# Remove leading and trailing spaces
sed 's/^[ \t]*//;s/[ \t]*$//' file

# Convert to lowercase
sed 's/.*/\L&/' file

# Convert to uppercase
sed 's/.*/\U&/' file

# Add line numbers
sed = file | sed 'N;s/\n/\t/'

# Remove line numbers
sed 's/^[ ]*[0-9]*[ ]*//' file

# Comment lines
sed 's/^/# /' file

# Uncomment lines
sed 's/^# //' file
```

## Awk Basics

### Syntax

```bash
awk 'pattern { action }' file
awk -F: '{ print $1 }' file    # Field separator
awk -v var=value '{ print var }' file    # Variables
```

### Built-in Variables

| Variable | Description |
|----------|-------------|
| `$0` | Entire line |
| `$1, $2, ...` | Field 1, 2, ... |
| `NF` | Number of fields |
| `NR` | Number of records (line number) |
| `FNR` | File number of records |
| `FS` | Field separator (default: whitespace) |
| `OFS` | Output field separator (default: space) |
| `RS` | Record separator (default: newline) |
| `ORS` | Output record separator (default: newline) |
| `FILENAME` | Current filename |

## Awk Commands

### Print

```bash
# Print entire line
awk '{ print }' file
awk '{ print $0 }' file

# Print specific fields
awk '{ print $1 }' file
awk '{ print $1, $3 }' file

# Print with separator
awk '{ print $1 ":" $2 }' file

# Print last field
awk '{ print $NF }' file

# Print second to last field
awk '{ print $(NF-1) }' file

# Print field and line number
awk '{ print NR, $1 }' file

# Print with custom OFS
awk 'BEGIN { OFS="\t" } { print $1, $2 }' file
```

### Patterns

```bash
# Lines matching pattern
awk '/pattern/' file

# Lines NOT matching pattern
awk '!/pattern/' file

# Lines starting with pattern
awk '/^pattern/' file

# Lines ending with pattern
awk '/pattern$/' file

# Specific field matches
awk '$3 == "value"' file
awk '$3 != "value"' file
awk '$3 ~ /pattern/' file    # Regex match
awk '$3 !~ /pattern/' file   # Negative regex match

# Numeric comparisons
awk '$3 > 100' file
awk '$3 >= 50 && $3 <= 100' file

# Multiple patterns
awk '/pattern1/ || /pattern2/' file
awk '/pattern1/ && /pattern2/' file
```

### Field Separator

```bash
# Colon separator
awk -F: '{ print $1 }' /etc/passwd

# Tab separator
awk -F'\t' '{ print $1 }' file

# Multiple separators
awk -F'[,:]' '{ print $1 }' file

# Regex separator
awk -F'[[:space:]]+' '{ print $1 }' file

# Set in BEGIN
awk 'BEGIN { FS=":" } { print $1 }' file
```

### BEGIN & END

```bash
# Header
awk 'BEGIN { print "Name\tAge" } { print $1, $2 }' file

# Footer
awk '{ sum += $1 } END { print "Total:", sum }' file

# Both
awk 'BEGIN { print "Starting" } { print $0 } END { print "Done" }' file

# Initialization
awk 'BEGIN { FS=":"; OFS="\t" } { print $1, $3 }' /etc/passwd
```

### Conditionals

```bash
# If statement
awk '{ if ($3 > 100) print $1 }' file

# If-else
awk '{ if ($3 > 100) print "High"; else print "Low" }' file

# Multiple conditions
awk '{ if ($3 > 100) print "High"; else if ($3 > 50) print "Medium"; else print "Low" }' file

# Ternary operator
awk '{ print ($3 > 100) ? "High" : "Low" }' file
```

### Loops

```bash
# For loop
awk '{ for (i=1; i<=NF; i++) print $i }' file

# While loop
awk '{ i=1; while (i<=NF) { print $i; i++ } }' file

# Do-while loop
awk '{ i=1; do { print $i; i++ } while (i<=NF) }' file

# Loop through fields
awk '{ for (i=1; i<=NF; i++) sum+=$i; print sum }' file
```

## Awk One-Liners

### Statistics

```bash
# Sum column
awk '{ sum += $1 } END { print sum }' file

# Average
awk '{ sum += $1; n++ } END { print sum/n }' file

# Count lines
awk 'END { print NR }' file

# Count matching lines
awk '/pattern/ { count++ } END { print count }' file

# Min and max
awk 'NR==1 { min=$1; max=$1 } { if ($1<min) min=$1; if ($1>max) max=$1 } END { print min, max }' file

# Sum, average, min, max
awk '{ sum+=$1; if (NR==1) {min=max=$1}; if ($1<min) min=$1; if ($1>max) max=$1 } END { print "Sum:", sum, "Avg:", sum/NR, "Min:", min, "Max:", max }' file
```

### Text Processing

```bash
# Print specific columns
awk '{ print $1, $3 }' file

# Swap columns
awk '{ print $2, $1 }' file

# Add column
awk '{ print $0, $1+$2 }' file

# Remove duplicates
awk '!seen[$0]++' file

# Count occurrences
awk '{ count[$1]++ } END { for (word in count) print word, count[word] }' file

# Reverse field order
awk '{ for (i=NF; i>0; i--) printf "%s%s", $i, (i>1 ? OFS : ORS) }' file

# Join lines
awk '{ printf "%s ", $0 } END { print "" }' file

# Split and print
awk '{ split($0, arr, ":"); print arr[1] }' file
```

### Filtering

```bash
# Print lines longer than 80 characters
awk 'length > 80' file

# Print lines with more than 5 fields
awk 'NF > 5' file

# Print odd-numbered lines
awk 'NR % 2 == 1' file

# Print even-numbered lines
awk 'NR % 2 == 0' file

# Print lines 10-20
awk 'NR >= 10 && NR <= 20' file

# Print every 5th line
awk 'NR % 5 == 0' file

# Print unique lines (in order)
awk '!seen[$0]++' file

# Print duplicate lines
awk 'seen[$0]++' file
```

### CSV Processing

```bash
# CSV to TSV
awk -F',' 'BEGIN { OFS="\t" } { $1=$1; print }' file.csv

# Extract column from CSV
awk -F',' '{ print $2 }' file.csv

# CSV with quoted fields
awk -F'","' '{ gsub(/^"|"$/, "", $1); print $1 }' file.csv

# Add column to CSV
awk -F',' 'BEGIN { OFS="," } { print $0, "new_value" }' file.csv

# Filter CSV rows
awk -F',' '$3 > 100' file.csv
```

### Log Analysis

```bash
# Count HTTP status codes
awk '{ print $9 }' access.log | sort | uniq -c

# Sum bytes transferred
awk '{ sum += $10 } END { print sum }' access.log

# Top 10 IPs
awk '{ print $1 }' access.log | sort | uniq -c | sort -rn | head

# Requests per hour
awk '{ print substr($4, 2, 14) }' access.log | uniq -c

# Filter by status code
awk '$9 == 500' access.log

# Calculate response time percentiles
awk '{ print $NF }' access.log | sort -n | awk '{ a[NR]=$1 } END { print "50th:", a[int(NR*0.5)], "95th:", a[int(NR*0.95)], "99th:", a[int(NR*0.99)] }'
```

### File Comparison

```bash
# Print lines in file1 not in file2
awk 'NR==FNR { a[$0]; next } !($0 in a)' file2 file1

# Print lines common to both files
awk 'NR==FNR { a[$0]; next } $0 in a' file1 file2

# Join two files on first field
awk 'NR==FNR { a[$1]=$2; next } { print $0, a[$1] }' file1 file2

# Merge columns from two files
paste file1 file2 | awk '{ print $1, $3 }'
```

## Practical Examples

### System Administration

```bash
# Parse /etc/passwd
awk -F: '{ print $1, $3, $6 }' /etc/passwd

# Users with UID >= 1000
awk -F: '$3 >= 1000 { print $1 }' /etc/passwd

# Find largest files
ls -lh | awk '$5 ~ /G$/ { print $9, $5 }'

# Process list summary
ps aux | awk '{ sum += $6 } END { print "Total memory:", sum/1024, "MB" }'

# Disk usage summary
df -h | awk '$5+0 > 80 { print $6, $5 }'

# Network connections by state
netstat -an | awk '/^tcp/ { state[$6]++ } END { for (s in state) print s, state[s] }'
```

### Data Processing

```bash
# Convert JSON array to CSV (simple)
sed 's/[{}\[\]]//g' data.json | sed 's/"//g' | awk -F, '{ print $1 "," $2 }'

# Extract URLs from HTML
sed 's/<a href="/\n/g' page.html | awk -F'"' '/^http/ { print $1 }'

# Parse Apache access log
awk '{ print $1 }' access.log | sort | uniq -c | sort -rn | head

# Generate report from CSV
awk -F',' 'NR==1 { print; next } { sum+=$3; count++ } END { print "Average:", sum/count }' data.csv

# Transpose CSV
awk -F',' '{ for (i=1; i<=NF; i++) a[i,NR]=$i; nf=NF } END { for (i=1; i<=nf; i++) { for (j=1; j<=NR; j++) printf "%s%s", a[i,j], (j<NR ? "," : "\n") } }' data.csv
```

### Configuration Files

```bash
# Remove comments and blank lines
sed '/^#/d; /^$/d' config.conf

# Extract values from key=value
awk -F= '/^[^#]/ { print $2 }' config.conf

# Change configuration value
sed -i 's/^DEBUG=.*/DEBUG=true/' config.conf

# Add line after pattern
sed '/\[section\]/a new_key=value' config.ini

# Validate JSON (basic check)
sed 's/[^{}[\],:]//g' file.json | awk '{ gsub(/[,:]/, ""); print } END { if (gsub(/{/, "&") != gsub(/}/, "&")) print "Unbalanced braces" }'
```

## Tips & Best Practices

### Performance

- Use `sed` for simple substitutions
- Use `awk` for field-based processing
- Avoid unnecessary pipes: `cat file | sed` → `sed file`
- Use `-n` with `sed` when you don't need all output
- Process files in place with `sed -i` instead of temp files

### Debugging

```bash
# Sed debugging
sed -n 'l' file    # Show special characters

# Awk debugging
awk '{ print "Debug:", $0 }' file

# Test patterns
echo "test string" | sed 's/pattern/replacement/'
echo "field1 field2" | awk '{ print $2 }'
```

### Common Pitfalls

```bash
# WRONG: Modifying file while reading
sed -i 's/old/new/' file.txt < file.txt

# CORRECT: Use -i with sed
sed -i 's/old/new/' file.txt

# WRONG: Using regex without escaping
sed 's/192.168.1.1/10.0.0.1/' file

# CORRECT: Escape dots
sed 's/192\.168\.1\.1/10.0.0.1/' file

# WRONG: Forgetting to set FS
awk '{ print $2 }' /etc/passwd

# CORRECT: Set field separator
awk -F: '{ print $2 }' /etc/passwd
```

## Resources

- [Sed Manual](https://www.gnu.org/software/sed/manual/)
- [Awk Manual](https://www.gnu.org/software/gawk/manual/)
- [Sed One-Liners](http://sed.sourceforge.net/sed1line.txt)
- [Awk One-Liners](http://www.pement.org/awk/awk1line.txt)
- [Regular Expressions](https://www.regular-expressions.info/)
