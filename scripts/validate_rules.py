import csv
import sys

# Set of seen rules based on key fields
seen = set()
duplicate_found = False
port_validation_failed = False

with open("rules.csv") as csvfile:
    reader = csv.DictReader(csvfile)
    for i, row in enumerate(reader, start=2):  # start=2 to match CSV line numbers (header is line 1)
        # Validate port field is numeric
        port = row["port"].strip()
        if not port.isdigit():
            print(f"❌ Non-numeric port detected on line {i}: port='{port}'")
            port_validation_failed = True
        
        key = (
            row["source_ip"].strip(),
            row["destination_ip"].strip(),
            port,
            row["protocol"].strip()
        )
        if key in seen:
            print(f"❌ Duplicate rule detected on line {i}: {key}")
            duplicate_found = True
        else:
            seen.add(key)

if port_validation_failed or duplicate_found:
    if port_validation_failed:
        print("\n❌ Validation failed: One or more non-numeric ports found.")
    if duplicate_found:
        print("❌ Validation failed: One or more duplicate rules found.")
    sys.exit(1)

print("✅ Validation passed: All ports are numeric and no duplicate rules found.")
