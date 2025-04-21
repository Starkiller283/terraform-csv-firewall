import csv
import sys

# Set of seen rules based on key fields
seen = set()
duplicate_found = False

with open("rules.csv") as csvfile:
    reader = csv.DictReader(csvfile)
    for i, row in enumerate(reader, start=2):  # start=2 to match CSV line numbers (header is line 1)
        key = (
            row["source_ip"].strip(),
            row["destination_ip"].strip(),
            row["port"].strip(),
            row["protocol"].strip()
        )
        if key in seen:
            print(f" Duplicate rule detected on line {i}: {key}")
            duplicate_found = True
        else:
            seen.add(key)

if duplicate_found:
    print(" Validation failed: One or more duplicate rules found.")
    sys.exit(1)

print(" Validation passed: No duplicate rules found.")
