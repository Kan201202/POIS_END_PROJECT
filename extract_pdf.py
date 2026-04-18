import sys
try:
    import pypdf
except ImportError:
    import subprocess
    subprocess.check_call([sys.executable, '-m', 'pip', 'install', 'pypdf'])
    import pypdf

pdf_path = sys.argv[1]
txt_path = sys.argv[2]
print(f"Reading {pdf_path}")
reader = pypdf.PdfReader(pdf_path)
text = ""
for page in reader.pages:
    extracted = page.extract_text()
    if extracted:
        text += extracted + "\n"

with open(txt_path, "w", encoding="utf-8") as f:
    f.write(text)
print(f"Saved to {txt_path}")
