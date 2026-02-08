#!/usr/bin/env python3
"""Extract Dao De Jing chapters from the Le Guin PDF into a plain text file.

Usage:
    pip install pymupdf
    python scripts/extract-ddj.py /path/to/pdf dao-de-jing.txt
"""
import sys
import re
import pymupdf as fitz

def extract_chapters(pdf_path, output_path):
    doc = fitz.open(pdf_path)
    full_text = ""
    for page in doc:
        full_text += page.get_text() + "\n"
    doc.close()

    # Split into chapters - Le Guin's chapters are numbered 1-81
    # Each chapter starts with a number and title
    chapters = []
    # Match chapter headings like "1\nTaoing" or "2\nSoul food"
    # The PDF text has chapter number on one line, title on next
    pattern = r'\n(\d{1,2})\n([A-Z][^\n]+)\n'
    splits = list(re.finditer(pattern, full_text))

    for i, match in enumerate(splits):
        ch_num = int(match.group(1))
        ch_title = match.group(2).strip()

        if ch_num < 1 or ch_num > 81:
            continue

        # Get text between this chapter and the next
        start = match.end()
        if i + 1 < len(splits):
            end = splits[i + 1].start()
        else:
            end = len(full_text)

        ch_text = full_text[start:end].strip()

        # Remove Le Guin's notes (they typically start with "Note" or are
        # separated by extra whitespace after the poem)
        # Try to find where the poem ends and notes begin
        # Notes often start with "NOTE" or have a different paragraph style
        note_markers = ["\nNOTE", "\nNote ", "\nNote\n", "\nMy ", "\nI ", "\nLao ",
                       "\nThis ", "\nA ", "\nThe ", "\nIn "]
        poem_end = len(ch_text)
        for marker in note_markers:
            idx = ch_text.find(marker)
            if idx > 50:  # Must be after some poem content
                # Check if this looks like a note paragraph (longer prose)
                after = ch_text[idx:idx+200]
                if len(after.split('\n')[1]) > 60 if '\n' in after[1:] else False:
                    poem_end = min(poem_end, idx)

        ch_text = ch_text[:poem_end].strip()

        chapters.append((ch_num, ch_title, ch_text))

    # Sort by chapter number and deduplicate
    seen = set()
    unique = []
    for ch in sorted(chapters, key=lambda x: x[0]):
        if ch[0] not in seen:
            seen.add(ch[0])
            unique.append(ch)

    # Write output
    with open(output_path, 'w') as f:
        for ch_num, ch_title, ch_text in unique:
            f.write(f"---\nCHAPTER {ch_num}: {ch_title}\n\n{ch_text}\n\n")

    print(f"Extracted {len(unique)} chapters to {output_path}")

    # Show any missing chapters
    found = {ch[0] for ch in unique}
    missing = set(range(1, 82)) - found
    if missing:
        print(f"Missing chapters: {sorted(missing)}")
        print("You may need to manually add these from the PDF.")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <pdf-path> <output-path>")
        sys.exit(1)
    extract_chapters(sys.argv[1], sys.argv[2])
