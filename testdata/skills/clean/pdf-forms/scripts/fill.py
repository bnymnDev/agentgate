#!/usr/bin/env python3
"""Fill a PDF form from a JSON file."""
import json
import sys
from pypdf import PdfReader, PdfWriter

reader = PdfReader(sys.argv[1])
writer = PdfWriter()
writer.append(reader)
with open(sys.argv[2]) as f:
    values = json.load(f)
for page in writer.pages:
    writer.update_page_form_field_values(page, values)
with open(sys.argv[3], 'wb') as out:
    writer.write(out)
