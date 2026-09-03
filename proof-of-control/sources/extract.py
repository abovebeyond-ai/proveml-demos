"""Extraction: what a machine infers from the invoice PDFs. pdftotext, then
regular expressions. The result is INFERRED, and says so: pdf digest, text
digest, method, and the fields, so that a person can check the mapping and
sign it (sign-mapping.mjs), and so a stranger can redo it.

usage: python3 extract.py
"""
import json, os, re, subprocess, hashlib, glob, datetime
HERE = os.path.dirname(os.path.abspath(__file__))
AS_OF = datetime.date(2026, 9, 4)   # the day the queue is worked; due_in_days is relative to it
sha = lambda b: hashlib.sha256(b).hexdigest()
pdftotext = subprocess.run(['pdftotext', '-v'], capture_output=True, text=True).stderr.splitlines()[0].strip()
out = {'as_of': AS_OF.isoformat(), 'method': pdftotext + ' + regular expressions (extract.py)', 'invoices': {}}
for pdf in sorted(glob.glob(os.path.join(HERE, 'invoices', '*.pdf'))):
    raw = open(pdf, 'rb').read()
    text = subprocess.run(['pdftotext', '-layout', pdf, '-'], capture_output=True, text=True).stdout
    open(pdf[:-4] + '.txt', 'w').write(text)
    g = lambda pat: (re.search(pat, text, re.M) or [None, None])[1]
    inv = g(r'^Invoice (inv-\d+)'); sup = re.search(r'^Supplier: (.+?) \((sup-\d+)\)', text, re.M)
    due = datetime.date.fromisoformat(g(r'^Due: (\d{4}-\d{2}-\d{2})'))
    fields = {'supplier': sup.group(2), 'supplier_name': sup.group(1), 'description': g(r'^Description: (.+)$').strip(),
              'amount': float(g(r'^Amount: ([\d.]+) ')), 'currency': g(r'^Amount: [\d.]+ ([A-Z]{3})'), 'due': due.isoformat(), 'due_in_days': (due - AS_OF).days}
    note = g(r'^Note: (.+)$')
    if note: fields['note'] = note.strip()
    out['invoices'][inv] = {'pdf': os.path.relpath(pdf, HERE), 'pdf_sha256': sha(raw), 'text_sha256': sha(text.encode()), 'fields': fields}
json.dump(out, open(os.path.join(HERE, 'extraction.json'), 'w'), indent=1)
print('extracted', len(out['invoices']), 'invoices with', pdftotext)
