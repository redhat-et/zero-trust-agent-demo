---
name: pdf-summary
description: Convert PDF documents to text and summarize them
---

# PDF summary skill

When asked to summarize a PDF document:

1. Use the exec tool to convert the PDF to text:
   `pdftotext input.pdf output.txt`
2. Use read_file to read the converted text
3. Summarize the content
