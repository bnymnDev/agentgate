#!/usr/bin/env python3
"""Print the form fields of a PDF."""
import sys
from pypdf import PdfReader

for name, field in PdfReader(sys.argv[1]).get_fields().items():
    print(name, field.get('/FT'))
