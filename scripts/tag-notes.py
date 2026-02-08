#!/usr/bin/env python3
"""Tag Le Guin's commentary notes in the extracted DDJ text.

Heuristic: poem lines are short (< 50 chars). When we hit a run of long
prose-like lines after the poem, that's commentary. Wrap it in [NOTE] tags.
"""
import re
import sys

def is_prose_line(line):
    """A line that looks like prose commentary rather than poetry."""
    stripped = line.strip()
    if not stripped:
        return False
    # Prose lines are typically > 55 chars and don't start with poem-like patterns
    return len(stripped) > 55

def tag_chapter(text):
    """Given the body text of a chapter (after the CHAPTER heading),
    find where the poem ends and commentary begins, and wrap commentary in [NOTE]."""
    lines = text.split('\n')

    # Find the transition from poem to prose
    # Walk backwards from the end to find where prose starts
    last_poem_line = len(lines) - 1

    # Skip trailing empty lines
    while last_poem_line >= 0 and not lines[last_poem_line].strip():
        last_poem_line -= 1

    if last_poem_line < 0:
        return text

    # Walk backwards through prose lines to find where poem ends
    prose_start = last_poem_line + 1
    i = last_poem_line
    consecutive_prose = 0
    while i >= 0:
        if is_prose_line(lines[i]):
            consecutive_prose += 1
            if consecutive_prose >= 2:
                # Found at least 2 consecutive prose lines - this is commentary
                # Walk back to find the start of the prose block
                while i >= 0 and (is_prose_line(lines[i]) or not lines[i].strip()):
                    i -= 1
                prose_start = i + 1
                break
        else:
            consecutive_prose = 0
        i -= 1

    if prose_start > last_poem_line:
        # No prose found
        return text

    # Check that there's actual content in the prose section
    prose_text = '\n'.join(lines[prose_start:]).strip()
    if len(prose_text) < 30:
        return text

    poem_part = '\n'.join(lines[:prose_start]).rstrip()
    note_part = '\n'.join(lines[prose_start:]).strip()

    return f"{poem_part}\n\n[NOTE]\n{note_part}\n[/NOTE]"

def process_file(input_path, output_path):
    with open(input_path) as f:
        content = f.read()

    chapters = content.split('---\n')
    result_parts = []

    for chunk in chapters:
        chunk = chunk.strip()
        if not chunk:
            continue

        # Split into heading and body
        match = re.match(r'(CHAPTER \d+: [^\n]+)\n\n(.*)', chunk, re.DOTALL)
        if match:
            heading = match.group(1)
            body = match.group(2)
            tagged_body = tag_chapter(body)
            result_parts.append(f"---\n{heading}\n\n{tagged_body}\n")
        else:
            result_parts.append(f"---\n{chunk}\n")

    with open(output_path, 'w') as f:
        f.write('\n'.join(result_parts))

    print(f"Tagged notes in {len(result_parts)} chapters -> {output_path}")

if __name__ == "__main__":
    if len(sys.argv) == 2:
        # In-place
        process_file(sys.argv[1], sys.argv[1])
    elif len(sys.argv) == 3:
        process_file(sys.argv[1], sys.argv[2])
    else:
        print(f"Usage: {sys.argv[0]} <input> [output]")
        sys.exit(1)
