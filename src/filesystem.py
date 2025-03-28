import os
import sys
import json
import difflib
import re
import subprocess
from pathlib import Path
from dataclasses import dataclass
from typing import List, Dict, Union, Optional, Tuple, Any
import fnmatch
from datetime import datetime

from mcp.server.fastmcp import FastMCP, Context

# Create MCP server
mcp = FastMCP("secure-filesystem-server")

# Command line argument parsing
if len(sys.argv) < 2:
    print("Usage: python mcp_server_filesystem.py <allowed-directory> [additional-directories...]", file=sys.stderr)
    sys.exit(1)

# Normalize all paths consistently
def normalize_path(p: str) -> str:
    return os.path.normpath(p)

def expand_home(filepath: str) -> str:
    if filepath.startswith('~/') or filepath == '~':
        return os.path.join(os.path.expanduser('~'), filepath[1:])
    return filepath

# Store allowed directories in normalized form
allowed_directories = [
    normalize_path(os.path.abspath(expand_home(dir)))
    for dir in sys.argv[1:]
]

# Validate that all directories exist and are accessible
for dir in sys.argv[1:]:
    expanded_dir = expand_home(dir)
    try:
        stats = os.stat(expanded_dir)
        if not os.path.isdir(expanded_dir):
            print(f"Error: {dir} is not a directory", file=sys.stderr)
            sys.exit(1)
    except Exception as e:
        print(f"Error accessing directory {dir}: {e}", file=sys.stderr)
        sys.exit(1)

def validate_path(requested_path: str) -> str:
    """
    Validate that a path is within allowed directories and safe to access.
    
    Args:
        requested_path: The path to validate
        
    Returns:
        The normalized, absolute path if valid
        
    Raises:
        ValueError: If the path is outside allowed directories or otherwise invalid
    """
    expanded_path = expand_home(requested_path)
    absolute = os.path.abspath(expanded_path)
    normalized_requested = normalize_path(absolute)
    
    # First, check if path is exactly one of the allowed directories or direct child
    if normalized_requested in allowed_directories:
        return normalized_requested
        
    # Check if path is within allowed directories
    is_allowed = False
    for dir_path in allowed_directories:
        if normalized_requested.startswith(dir_path):
            is_allowed = True
            break
            
    if not is_allowed:
        raise ValueError(f"Access denied - path outside allowed directories: {absolute}")
    
    # Handle symlinks for existing paths
    if os.path.exists(normalized_requested):
        try:
            real_path = os.path.realpath(absolute)
            normalized_real = normalize_path(real_path)
            
            # Check if real path is still in allowed directories
            is_real_allowed = False
            for dir_path in allowed_directories:
                if normalized_real.startswith(dir_path):
                    is_real_allowed = True
                    break
                    
            if not is_real_allowed:
                raise ValueError("Access denied - symlink target outside allowed directories")
                
            return real_path
        except Exception as e:
            if 'recursion' in str(e).lower():
                raise ValueError("Path contains circular symlinks")
            raise ValueError(f"Error validating path: {str(e)}")
    else:
        # For non-existing paths, verify parent directory exists and is allowed
        parent_dir = os.path.dirname(absolute)
        
        if not os.path.exists(parent_dir):
            raise ValueError(f"Parent directory does not exist: {parent_dir}")
            
        try:
            parent_real_path = os.path.realpath(parent_dir)
            normalized_parent = normalize_path(parent_real_path)
            
            # Check if parent is in allowed directories
            is_parent_allowed = False
            for dir_path in allowed_directories:
                if normalized_parent.startswith(dir_path):
                    is_parent_allowed = True
                    break
                    
            if not is_parent_allowed:
                raise ValueError("Access denied - parent directory outside allowed directories")
                
            return absolute
        except Exception as e:
            if 'recursion' in str(e).lower():
                raise ValueError("Path contains circular symlinks")
            raise ValueError(f"Error validating parent directory: {str(e)}")


# Helper functions for file operations
def get_file_stats(file_path: str) -> Dict[str, Any]:
    stats = os.stat(file_path)
    return {
        "size": stats.st_size,
        "created": datetime.fromtimestamp(stats.st_ctime),
        "modified": datetime.fromtimestamp(stats.st_mtime),
        "accessed": datetime.fromtimestamp(stats.st_atime),
        "isDirectory": os.path.isdir(file_path),
        "isFile": os.path.isfile(file_path),
        "permissions": oct(stats.st_mode)[-3:],
    }

# Common function for getting file metadata
def get_metadata(path, is_file, count_lines=False, show_permissions=False, show_owner=False, show_size=False):
    """
    Get formatted metadata for a file or directory.
    
    Args:
        path: The path to get metadata for
        is_file: Whether this is a file (True) or directory (False)
        count_lines: Whether to include line count for files
        show_permissions: Whether to include permissions
        show_owner: Whether to include owner/group info
        show_size: Whether to include size info
        
    Returns:
        A comma-separated string of metadata, or empty string if no metadata requested
    """
    import pwd
    import grp
    
    metadata_parts = []
    
    try:
        stats = os.stat(path)
        
        if show_size:
            # Format size in human-readable format
            size_bytes = stats.st_size
            if size_bytes < 1024:
                size_str = f"{size_bytes}B"
            elif size_bytes < 1024 * 1024:
                size_str = f"{size_bytes/1024:.1f}KB"
            elif size_bytes < 1024 * 1024 * 1024:
                size_str = f"{size_bytes/(1024*1024):.1f}MB"
            else:
                size_str = f"{size_bytes/(1024*1024*1024):.1f}GB"
            metadata_parts.append(size_str)
        
        if show_permissions:
            # Format permissions similar to ls -l
            perms = ""
            mode = stats.st_mode
            perms += "d" if os.path.isdir(path) else "-"
            perms += "r" if mode & 0o400 else "-"
            perms += "w" if mode & 0o200 else "-"
            perms += "x" if mode & 0o100 else "-"
            perms += "r" if mode & 0o040 else "-"
            perms += "w" if mode & 0o020 else "-"
            perms += "x" if mode & 0o010 else "-"
            perms += "r" if mode & 0o004 else "-"
            perms += "w" if mode & 0o002 else "-"
            perms += "x" if mode & 0o001 else "-"
            metadata_parts.append(perms)
        
        if show_owner:
            try:
                # Get username and group
                user = pwd.getpwuid(stats.st_uid).pw_name
                group = grp.getgrgid(stats.st_gid).gr_name
                metadata_parts.append(f"{user}:{group}")
            except (KeyError, ImportError):
                # Fallback if lookup fails
                metadata_parts.append(f"{stats.st_uid}:{stats.st_gid}")
                
        # Add line count for files
        if count_lines and is_file:
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    line_count = sum(1 for _ in f)
                metadata_parts.append(f"{line_count} lines")
            except Exception:
                # Handle binary files or other reading errors
                metadata_parts.append("binary")
                
    except Exception as e:
        if show_size or show_permissions or show_owner:
            metadata_parts.append(f"Error: {str(e)}")
            
    return ", ".join(metadata_parts)



# Define tool implementations
@mcp.tool()
def read_file(path: str) -> str:
    """
    Read the complete contents of a file from the file system.
    Handles various text encodings and provides detailed error messages
    if the file cannot be read. Use this tool when you need to examine
    the contents of a single file. Only works within allowed directories.
    """
    validated_path = validate_path(path)
    with open(validated_path, 'r', encoding='utf-8') as f:
        return f.read()

@mcp.tool()
def read_multiple_files(paths: List[str]) -> str:
    """
    Read the contents of multiple files simultaneously. This is more
    efficient than reading files one by one when you need to analyze
    or compare multiple files. Each file's content is returned with its
    path as a reference. Failed reads for individual files won't stop
    the entire operation. Only works within allowed directories.
    """
    results = []
    
    for file_path in paths:
        try:
            validated_path = validate_path(file_path)
            with open(validated_path, 'r', encoding='utf-8') as f:
                content = f.read()
            results.append(f"{file_path}:\n{content}\n")
        except Exception as e:
            results.append(f"{file_path}: Error - {str(e)}")
    
    return "\n---\n".join(results)

@mcp.tool()
def read_file_by_line(path: str, ranges: List[str]) -> str:
    """
    Read specific lines or line ranges from a file.
    Ranges can be specified as single numbers (e.g., "5") or ranges (e.g., "10-20").
    Examples: ["5", "10-20", "100"] will read line 5, lines 10 through 20, and line 100.
    Only works within allowed directories.
    """
    validated_path = validate_path(path)
    
    # Parse the ranges
    line_numbers = set()
    for r in ranges:
        if '-' in r:
            start, end = map(int, r.split('-'))
            line_numbers.update(range(start, end + 1))
        else:
            line_numbers.add(int(r))
    
    # Read the file line by line, keeping only requested lines
    with open(validated_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    
    # Filter lines by the requested line numbers (1-indexed)
    selected_lines = [(i+1, line) for i, line in enumerate(lines) if i+1 in line_numbers]
    
    if not selected_lines:
        return "No matching lines found."
    
    # Format the output with line numbers
    return "\n".join(f"{line_num}: {line.rstrip()}" for line_num, line in selected_lines)

@mcp.tool()
def read_file_by_keyword(path: str, keyword: str, before: int = 0, after: int = 0, use_regex: bool = False, ignore_case: bool = False) -> str:
    """
    Read lines containing a keyword or matching a regex pattern, with optional context.
    Overlapping regions are combined.
    
    Args:
        path: Path to the file
        keyword: The keyword to search for, or a regex pattern if use_regex is True
        before: Number of lines to include before each match (default: 0)
        after: Number of lines to include after each match (default: 0)
        use_regex: Whether to interpret the keyword as a regular expression (default: False)
        ignore_case: Whether to ignore case when matching (default: False)
    
    Returns:
        Matching lines with context, or a message if no matches are found.
    """
    validated_path = validate_path(path)
    
    with open(validated_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    
    # Find all lines containing the keyword or matching the regex
    matches = []
    if use_regex:
        try:
            # Use re.IGNORECASE flag if ignore_case is True
            flags = re.IGNORECASE if ignore_case else 0
            pattern = re.compile(keyword, flags)
            matches = [i for i, line in enumerate(lines) if pattern.search(line)]
        except re.error as e:
            return f"Error in regex pattern: {str(e)}"
    else:
        if ignore_case:
            # Case-insensitive keyword search
            keyword_lower = keyword.lower()
            matches = [i for i, line in enumerate(lines) if keyword_lower in line.lower()]
        else:
            # Case-sensitive keyword search
            matches = [i for i, line in enumerate(lines) if keyword in line]
    
    if not matches:
        case_str = "case-insensitive " if ignore_case else ""
        return f"No matches found for {case_str}{'pattern' if use_regex else 'keyword'} '{keyword}'."
    
    # Determine the ranges of lines to include (with context)
    regions = []
    for match in matches:
        start = max(0, match - before)
        end = min(len(lines) - 1, match + after)
        regions.append((start, end))
    
    # Combine overlapping regions
    combined_regions = []
    regions.sort()
    current_start, current_end = regions[0]
    
    for start, end in regions[1:]:
        if start <= current_end + 1:
            # Regions overlap or are adjacent, merge them
            current_end = max(current_end, end)
        else:
            # New non-overlapping region
            combined_regions.append((current_start, current_end))
            current_start, current_end = start, end
    
    combined_regions.append((current_start, current_end))
    
    # Extract the lines from the combined regions
    result = []
    
    # Create pattern for regex mode or None for keyword mode
    if use_regex:
        flags = re.IGNORECASE if ignore_case else 0
        pattern = re.compile(keyword, flags)
    else:
        pattern = None
    
    for start, end in combined_regions:
        # Add a separator between regions if needed
        if result:
            result.append("---")
        
        # Add the region with line numbers
        for i in range(start, end + 1):
            line_num = i + 1  # 1-indexed line numbers
            line = lines[i].rstrip()
            
            # Mark matching lines
            if use_regex:
                is_match = pattern.search(line) is not None
            else:
                if ignore_case:
                    is_match = keyword.lower() in line.lower()
                else:
                    is_match = keyword in line
            
            prefix = ">" if is_match else " "
            result.append(f"{line_num}{prefix} {line}")
    
    return "\n".join(result)

@mcp.tool()
def read_function_by_keyword(path: str, keyword: str, before: int = 0, use_regex: bool = False) -> str:
    """
    Read a function definition from a file by keyword or regex pattern.
    
    Searches for the keyword, then captures the function definition by:
    1. Looking for an opening brace after the keyword
    2. Tracking brace nesting to find the matching closing brace
    3. Including the specified number of lines before the function
    
    Args:
        path: Path to the file
        keyword: Keyword to identify the function (usually the function name), or a regex pattern if use_regex is True
        before: Number of lines to include before the function definition
        use_regex: Whether to interpret the keyword as a regular expression (default: False)
    
    Returns:
        The function definition with context, or a message if not found
    """
    validated_path = validate_path(path)
    
    with open(validated_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    
    # Find lines containing the keyword or matching the regex
    matches = []
    if use_regex:
        try:
            pattern = re.compile(keyword)
            matches = [i for i, line in enumerate(lines) if pattern.search(line)]
        except re.error as e:
            return f"Error in regex pattern: {str(e)}"
    else:
        matches = [i for i, line in enumerate(lines) if keyword in line]
    
    if not matches:
        return f"No matches found for {'pattern' if use_regex else 'keyword'} '{keyword}'."
    
    for match_idx in matches:
        # Check if this is a function definition by looking for braces
        line_idx = match_idx
        brace_idx = -1
        
        # Look for opening brace on the same line or the next few lines
        for i in range(line_idx, min(line_idx + 3, len(lines))):
            if '{' in lines[i]:
                brace_idx = i
                break
        
        if brace_idx == -1:
            continue  # Not a function definition with braces, try next match
        
        # Track brace nesting to find the end of the function
        brace_count = 0
        end_idx = -1
        
        for i in range(brace_idx, len(lines)):
            line = lines[i]
            brace_count += line.count('{')
            brace_count -= line.count('}')
            
            if brace_count == 0:
                end_idx = i
                break
        
        if end_idx == -1:
            return f"Found function at line {match_idx + 1}, but could not locate matching closing brace."
        
        # Include the requested number of lines before the function
        start_idx = max(0, match_idx - before)
        
        # Extract the function with line numbers
        result = []
        for i in range(start_idx, end_idx + 1):
            line_num = i + 1  # 1-indexed line numbers
            line = lines[i].rstrip()
            result.append(f"{line_num}: {line}")
        
        return "\n".join(result)
    
    return f"Found {'pattern matches' if use_regex else f'keyword \'{keyword}\''} but no valid function definition with braces was identified."



@mcp.tool()
def write_file(path: str, content: str) -> str:
    """
    Create a new file or completely overwrite an existing file with new content.
    Use with caution as it will overwrite existing files without warning.
    Handles text content with proper encoding. Only works within allowed directories.
    """
    validated_path = validate_path(path)
    with open(validated_path, 'w', encoding='utf-8') as f:
        f.write(content)
    return f"Successfully wrote to {path}"

@mcp.tool()
def edit_file_diff(path: str, replacements: Dict[str, str] = None, inserts: Dict[str, str] = None, 
                 replace_all: bool = True, dry_run: bool = False) -> str:
    """
    Edit a file by replacing existing content with new content without specifying line numbers.
    
    Args:
        path: Path to the file to edit
        replacements: Dictionary where keys are existing content to find and values are new content to replace it with
        inserts: Dictionary of insertions with the following format:
                - key: Existing content to find (or special cases)
                - value: New content to insert after the found content
                Special insertion keys:
                - Empty string "": Insert at the BEGINNING of the file
                - Any existing content: Insert after that content
        replace_all: If True, replace all occurrences of the text; if False, replace only the first occurrence
        dry_run: If True, only validate but don't apply changes
        
    Returns:
        A message indicating the changes applied or validation result
    
    Example:
        edit_file_diff(
            "myfile.py",
            replacements={
                "def old_function():\\n    return False\\n": "def new_function():\\n    return True\\n",
                "MAX_RETRIES = 3": "MAX_RETRIES = 5"
            },
            inserts={
                "": "# Insert comment at beginning of file\\n",
                "import os": "import sys\\nimport logging\\n",
                "def main():": "    # Main function follows\\n",
                "return result  # last line": "# End of file\\n"
            },
            replace_all=False
        )
    """
    validated_path = validate_path(path)
    
    # Set default values
    if replacements is None:
        replacements = {}
    if inserts is None:
        inserts = {}
    
    # Read the original file
    try:
        with open(validated_path, 'r', encoding='utf-8') as f:
            content = f.read()
    except Exception as e:
        return f"Error reading file: {str(e)}"
    
    # Make a copy of original content to modify
    new_content = content
    
    # Keep track of operations for reporting
    operations = {
        "replace": 0,
        "insert": 0,
        "errors": []
    }
    
    # Process replacements
    for old_text, new_text in replacements.items():
        if not old_text:
            operations["errors"].append("Error: Empty string cannot be used as a replacement key")
            continue
            
        # Handle newline differences
        old_text_normalized = old_text.replace('\r\n', '\n')
        new_content_normalized = new_content.replace('\r\n', '\n')
        
        # Check if the text exists in the file
        if old_text_normalized not in new_content_normalized:
            operations["errors"].append(f"Error: Text to replace not found: {old_text[:50]}...")
            continue
        
        # Apply replacement
        if not dry_run:
            if replace_all:
                # Replace all occurrences
                count_before = new_content_normalized.count(old_text_normalized)
                new_content = new_content.replace(old_text, new_text)
                operations["replace"] += count_before
            else:
                # Replace only first occurrence
                pos = new_content_normalized.find(old_text_normalized)
                if pos >= 0:
                    # Get original string encoding (not normalized)
                    actual_old_text = new_content[pos:pos + len(old_text)]
                    new_content = new_content.replace(actual_old_text, new_text, 1)
                    operations["replace"] += 1
    
    # Process insertions
    for anchor_text, insert_text in inserts.items():
        if anchor_text is None or anchor_text == "":
            # Insert at the BEGINNING of the file
            if not dry_run:
                new_content = insert_text + new_content
            operations["insert"] += 1
            continue
            
        # Handle newline differences
        anchor_text_normalized = anchor_text.replace('\r\n', '\n')
        new_content_normalized = new_content.replace('\r\n', '\n')
        
        # Check if the anchor text exists in the file
        if anchor_text_normalized not in new_content_normalized:
            operations["errors"].append(f"Error: Anchor text for insertion not found: {anchor_text[:50]}...")
            continue
            
        if not dry_run:
            if replace_all:
                # Insert after each occurrence of the anchor text
                parts = []
                remainder = new_content
                remainder_normalized = remainder.replace('\r\n', '\n')
                
                while anchor_text_normalized in remainder_normalized:
                    # Find the position in the normalized text
                    pos = remainder_normalized.find(anchor_text_normalized)
                    
                    # Map to the original text position
                    actual_anchor_end = pos + len(anchor_text)
                    
                    # Add the part before and including the anchor
                    parts.append(remainder[:actual_anchor_end])
                    
                    # Add the insertion
                    parts.append(insert_text)
                    
                    # Continue with the remainder
                    remainder = remainder[actual_anchor_end:]
                    remainder_normalized = remainder.replace('\r\n', '\n')
                    
                    operations["insert"] += 1
                
                # Add any remaining content
                parts.append(remainder)
                
                # Combine all parts
                new_content = "".join(parts)
            else:
                # Insert after first occurrence only
                pos = new_content_normalized.find(anchor_text_normalized)
                if pos >= 0:
                    # Find the end of the actual anchor text in the original string
                    actual_end_pos = pos + len(anchor_text)
                    
                    # Insert the new text after the anchor
                    new_content = new_content[:actual_end_pos] + insert_text + new_content[actual_end_pos:]
                    operations["insert"] += 1
    
    # Write the modified content if not in dry run mode and no errors occurred
    if not dry_run and not operations["errors"]:
        try:
            with open(validated_path, 'w', encoding='utf-8') as f:
                f.write(new_content)
        except Exception as e:
            return f"Error writing to file: {str(e)}"
    
    # Create a summary of changes
    if operations["errors"]:
        return "Errors occurred during edit:\n" + "\n".join(operations["errors"])
    else:
        changes = []
        for op_type, count in operations.items():
            if op_type != "errors" and count > 0:
                changes.append(f"{count} {op_type} operation{'s' if count > 1 else ''}")
        
        action = "Validated" if dry_run else "Applied"
        if changes:
            return f"{action} {', '.join(changes)} to {path}"
        else:
            return f"No changes were made to {path}"


@mcp.tool()
def edit_file_diff_line(path: str, edits: Dict[str, str], dry_run: bool = False) -> str:
    """
    Edit a file using a diff approach specifying exact line number locations.
    Note that all line numbers refer to the original file before any edits.
    Line numbers start at 1.
    Prefer using `edit_file_diff`, unless you know the exact line number locations for each edit operation.
    
    Args:
        path: Path to the file to edit
        edits: Dictionary of edits with the following pattern:
          - "N": Replace line N with the provided content
          - "N-M": Replace lines N through M with the provided content 
                   (empty string removes the lines)
          - "Ni": Insert the provided content after line N 
                  (use "0i" to insert at the beginning)
          - "a": Append the provided content at the end of the file
        dry_run: If True, only validate but don't apply changes
        
    Returns:
        A message indicating the changes applied or validation result
    
    Example:
        edit_file("myfile.py", {
            "5": "def new_function():\\n",       # Replace line 5
            "10-12": "# New content\\n",         # Replace lines 10-12
            "6-8": "",                          # Delete lines 6-8
            "0i": "# File header\\n",            # Insert at the beginning
            "15i": "# Insert after line 15\\n",   # Insert after line 15
            "a": "# End of file\\n"              # Append to the end
            "7": "\\n"                           # Replace line 7 with empty line
        })
    """
    validated_path = validate_path(path)
    
    # Read the original file
    try:
        with open(validated_path, 'r', encoding='utf-8') as f:
            original_lines = f.readlines()
    except Exception as e:
        return f"Error reading file: {str(e)}"
    
    # Make a copy of original lines to modify
    new_lines = original_lines.copy()
    
    # Parse edits into structured format with consistent fields
    structured_edits = []
    errors = []
    
    for line_spec, content in edits.items():
        # Handle special append case
        if line_spec.lower() == "a":
            structured_edits.append({
                "type": "insert",
                "start": len(new_lines),  # Insert after the last line
                "content": content
            })
            continue
            
        # Handle insertion with "Ni" pattern
        if line_spec.endswith("i"):
            try:
                line_num = int(line_spec[:-1])
                if line_num < 0 or line_num > len(new_lines):
                    errors.append(f"Error: Line number {line_num} out of range (0-{len(new_lines)}) for insertion")
                    continue
                    
                structured_edits.append({
                    "type": "insert",
                    "start": line_num,
                    "content": content
                })
            except ValueError:
                errors.append(f"Error: Invalid insertion specification '{line_spec}'. Must be in format 'Ni' where N is a line number.")
            continue
            
        # Handle replacement (either single line or range)
        if "-" in line_spec:
            # Range specified
            try:
                line_start, line_end = map(int, line_spec.split("-"))
                
                if line_start < 1 or line_start > len(new_lines):
                    errors.append(f"Error: Start line {line_start} out of range (1-{len(new_lines)}) for replacement")
                    continue
                    
                if line_end < 1 or line_end > len(new_lines):
                    errors.append(f"Error: End line {line_end} out of range (1-{len(new_lines)}) for replacement")
                    continue
                    
                if line_end < line_start:
                    errors.append(f"Error: End line {line_end} is before start line {line_start}")
                    continue
                    
                structured_edits.append({
                    "type": "replace",
                    "start": line_start,
                    "end": line_end,
                    "content": content
                })
            except ValueError:
                errors.append(f"Error: Invalid line range specification '{line_spec}'. Must be in format 'N-M' where N, M are line numbers.")
        else:
            # Single line specified
            try:
                line_num = int(line_spec)
                
                if line_num < 1 or line_num > len(new_lines):
                    errors.append(f"Error: Line number {line_num} out of range (1-{len(new_lines)}) for replacement")
                    continue
                    
                structured_edits.append({
                    "type": "replace",
                    "start": line_num,
                    "end": line_num,
                    "content": content
                })
            except ValueError:
                errors.append(f"Error: Invalid line number '{line_spec}'. Must be an integer.")
    
    # Return early if there are parsing errors
    if errors:
        return "Errors occurred during parsing:\n" + "\n".join(errors)
    
    # Sort edits by line number (descending) to process from bottom to top
    structured_edits.sort(key=lambda e: e["start"], reverse=True)
    
    # Keep track of operations for reporting
    operations = {
        "replace": 0,
        "insert": 0,
        "errors": []
    }
    
    # Process edits
    for edit in structured_edits:
        edit_type = edit["type"]
        
        if edit_type == "replace":
            line_start = edit["start"]
            line_end = edit["end"]
            content = edit["content"]
            
            # Prepare content lines
            content_lines = []
            if content:
                content_lines = content.splitlines(True)  # Keep the line endings
                
                # Ensure all lines end with newline except possibly the last one
                for i in range(len(content_lines)):
                    if i < len(content_lines) - 1 and not content_lines[i].endswith('\n'):
                        content_lines[i] += '\n'
                
                # Make sure the last line has a newline if the file had one
                if content_lines and not content_lines[-1].endswith('\n'):
                    if line_end < len(new_lines) and new_lines[line_end-1].endswith('\n'):
                        content_lines[-1] += '\n'
            
            if not dry_run:
                # Replace the specified lines (adjust for 0-indexed list)
                new_lines[line_start-1:line_end] = content_lines
                
            operations["replace"] += 1
            
        elif edit_type == "insert":
            line_num = edit["start"]
            content = edit["content"]
            
            # Prepare content lines
            content_lines = []
            if content:
                content_lines = content.splitlines(True)
                
                # Ensure all lines end with newline except possibly the last one
                for i in range(len(content_lines)):
                    if i < len(content_lines) - 1 and not content_lines[i].endswith('\n'):
                        content_lines[i] += '\n'
                
                # Make sure the last line has a newline if inserting in the middle of the file
                if content_lines and not content_lines[-1].endswith('\n'):
                    if line_num < len(new_lines) and line_num > 0 and new_lines[0].endswith('\n'):
                        content_lines[-1] += '\n'
            
            if not dry_run:
                # Insert at the specified position
                if line_num == 0:
                    # Insert at the beginning
                    new_lines[0:0] = content_lines
                else:
                    # Insert after the specified line (adjust for 0-indexed list)
                    new_lines[line_num:line_num] = content_lines
                
            operations["insert"] += 1
    
    # Write the modified content if not in dry run mode and no errors occurred
    if not dry_run and not operations["errors"]:
        try:
            with open(validated_path, 'w', encoding='utf-8') as f:
                f.writelines(new_lines)
        except Exception as e:
            return f"Error writing to file: {str(e)}"
    
    # Create a summary of changes
    if operations["errors"]:
        return "Errors occurred during edit:\n" + "\n".join(operations["errors"])
    else:
        changes = []
        for op_type, count in operations.items():
            if op_type != "errors" and count > 0:
                changes.append(f"{count} {op_type} operation{'s' if count > 1 else ''}")
        
        action = "Validated" if dry_run else "Applied"
        if changes:
            return f"{action} {', '.join(changes)} to {path}"
        else:
            return f"No changes were made to {path}"
    
@mcp.tool()
def create_directory(path: str) -> str:
    """
    Create a new directory or ensure a directory exists. Can create multiple
    nested directories in one operation. If the directory already exists,
    this operation will succeed silently. Perfect for setting up directory
    structures for projects or ensuring required paths exist. Only works within allowed directories.
    """
    validated_path = validate_path(path)
    os.makedirs(validated_path, exist_ok=True)
    return f"Successfully created directory {path}"

@mcp.tool()
def list_directory(path: str) -> str:
    """
    Get a detailed listing of all files and directories in a specified path.
    Results clearly distinguish between files and directories with [FILE] and [DIR]
    prefixes. This tool is essential for understanding directory structure and
    finding specific files within a directory. Only works within allowed directories.
    """
    validated_path = validate_path(path)
    entries = os.listdir(validated_path)
    
    formatted = []
    for entry in entries:
        entry_path = os.path.join(validated_path, entry)
        prefix = "[DIR]" if os.path.isdir(entry_path) else "[FILE]"
        formatted.append(f"{prefix} {entry}")
    
    return "\n".join(formatted)

@mcp.tool()
def directory_tree(path: str, count_lines: bool = False, show_permissions: bool = False, 
                  show_owner: bool = False, show_size: bool = False) -> str:
    """
    Get a recursive listing of files and directories with optional metadata.
    
    Args:
        path: Path to the directory to display
        count_lines: Whether to include the number of lines for each file (default: False)
        show_permissions: Whether to show file permissions (default: False)
        show_owner: Whether to show file ownership information (default: False)
        show_size: Whether to show file sizes (default: False)
        
    Returns:
        A text representation of directories and files with full paths and requested metadata
    """
    validated_path = validate_path(path)
    output_lines = []
    
    def process_directory(current_path):
        result = []
        
        try:
            entries = sorted(os.listdir(current_path))
        except PermissionError:
            return [f"{current_path} [Permission denied]"]
        except Exception as e:
            return [f"{current_path} [Error: {str(e)}]"]
        
        # Add the directory itself with trailing slash
        metadata = get_metadata(
            current_path, 
            False, 
            count_lines, 
            show_permissions, 
            show_owner, 
            show_size
        )
        dir_entry = current_path + "/"
        if metadata:
            dir_entry += f" [{metadata}]"
        result.append(dir_entry)
        
        # Process all children
        for entry in entries:
            entry_path = os.path.join(current_path, entry)
            
            if os.path.isdir(entry_path):
                # Process directories recursively
                result.extend(process_directory(entry_path))
            else:
                # Process files
                metadata = get_metadata(
                    entry_path, 
                    True, 
                    count_lines, 
                    show_permissions, 
                    show_owner, 
                    show_size
                )
                file_entry = entry_path
                if metadata:
                    file_entry += f" [{metadata}]"
                result.append(file_entry)
        
        return result
    
    # Process the root directory and all its contents
    output_lines = process_directory(validated_path)
    return "\n".join(output_lines)


@mcp.tool()
def git_directory_tree(path: str, count_lines: bool = False, show_permissions: bool = False, 
                      show_owner: bool = False, show_size: bool = False) -> str:
    """
    Get a recursive listing of git-tracked files and directories with optional metadata.
    
    Args:
        path: Path to the git repository directory
        count_lines: Whether to include the number of lines for each file (default: False)
        show_permissions: Whether to show file permissions (default: False)
        show_owner: Whether to show file ownership information (default: False)
        show_size: Whether to show file sizes (default: False)
        
    Returns:
        A text representation of git-tracked files with full paths and requested metadata
    """
    import shutil
    from pathlib import Path
    
    validated_path = validate_path(path)
    
    # Check if this is a git repository
    git_dir = os.path.join(validated_path, '.git')
    if not os.path.isdir(git_dir):
        return f"Error: {path} is not a git repository (no .git directory found)."
    
    # Find git executable
    git_cmd = shutil.which('git')
    if not git_cmd:
        # Try common locations for git if shutil.which fails
        common_git_paths = [
            '/usr/bin/git',
            '/usr/local/bin/git',
            '/opt/homebrew/bin/git',
            'C:\\Program Files\\Git\\bin\\git.exe',
            'C:\\Program Files (x86)\\Git\\bin\\git.exe'
        ]
        for git_path in common_git_paths:
            if os.path.isfile(git_path):
                git_cmd = git_path
                break
        
        if not git_cmd:
            return "Error: Git executable not found. Please ensure Git is installed and in your PATH."
    
    try:
        # Change into the repository directory and run git ls-files
        original_dir = os.getcwd()
        os.chdir(validated_path)
        
        try:
            # git config --global --add safe.directory /path
            subprocess.run(
                [git_cmd, 'config', '--global', '--add', 'safe.directory', validated_path], 
                capture_output=False, 
                text=False,
                check=False
            )
            
            # Run git ls-files to get all tracked files
            result = subprocess.run(
                [git_cmd, 'ls-files'], 
                capture_output=True, 
                text=True,
                check=True
            )
            
            git_files = list(result.stdout.strip().split('\n'))
            if not git_files or (len(git_files) == 1 and not git_files[0]):
                return "No tracked files found in the repository."
            
            # Add repository root as the first entry
            output_lines = [f"{validated_path}/ [git repository root]"]
            
            # Collect tracked files
            for rel_file in git_files:
                if not rel_file:  # Skip empty lines
                    continue
                    
                # Skip .git directory and its contents
                if rel_file.startswith('.git/'):
                    continue
                
                file_path = os.path.join(validated_path, rel_file)
                
                # Get and add metadata
                if os.path.exists(file_path):
                    metadata = get_metadata(
                        file_path, 
                        True, 
                        count_lines, 
                        show_permissions, 
                        show_owner, 
                        show_size
                    )
                    if metadata:
                        output_lines.append(f"{file_path} [{metadata}]")
                    else:
                        output_lines.append(file_path)
                else:
                    # Handle case where file is tracked but doesn't exist locally
                    output_lines.append(f"{file_path} [tracked but missing]")
            
            return "\n".join(output_lines)
            
        finally:
            # Ensure we change back to the original directory even if an error occurs
            if os.getcwd() != original_dir:
                os.chdir(original_dir)
            
    except subprocess.CalledProcessError as e:
        return f"Error executing git command: {e.stderr}"
    except Exception as e:
        return f"Error processing git repository: {str(e)}"

@mcp.tool()
def move_file(source: str, destination: str) -> str:
    """
    Move or rename files and directories. Can move files between directories
    and rename them in a single operation. If the destination exists, the
    operation will fail. Works across different directories and can be used
    for simple renaming within the same directory. Both source and destination must be within allowed directories.
    """
    valid_source_path = validate_path(source)
    valid_dest_path = validate_path(destination)
    
    os.rename(valid_source_path, valid_dest_path)
    return f"Successfully moved {source} to {destination}"

@mcp.tool()
def search_files(path: str, pattern: str, excludePatterns: Optional[List[str]] = None) -> str:
    """
    Recursively search for files and directories matching a pattern.
    Searches through all subdirectories from the starting path. The search
    is case-insensitive and matches partial names. Returns full paths to all
    matching items. Only searches within allowed directories.
    """
    if excludePatterns is None:
        excludePatterns = []
    
    validated_path = validate_path(path)
    results = []
    
    # Using os.walk instead of recursive function to avoid recursion depth issues
    for root, dirs, files in os.walk(validated_path):
        # Validate each directory to ensure it's within allowed paths
        # but don't follow symlinks to prevent loops
        i = 0
        while i < len(dirs):
            dir_path = os.path.join(root, dirs[i])
            try:
                # Skip validation if dir is in excluded patterns
                rel_path = os.path.relpath(dir_path, validated_path)
                should_exclude = any(
                    fnmatch.fnmatch(rel_path, '*/' + pat + '/*') if '*' not in pat else fnmatch.fnmatch(rel_path, pat)
                    for pat in excludePatterns
                )
                
                if should_exclude:
                    dirs.pop(i)  # Remove from dirs to skip processing
                    continue
                    
                # We only need to validate the path, but don't need the return value
                validate_path(dir_path)
                i += 1
            except Exception:
                # If validation fails, skip this directory
                dirs.pop(i)
        
        # Check directories for matches
        for dir_name in dirs:
            if pattern.lower() in dir_name.lower():
                results.append(os.path.join(root, dir_name))
        
        # Check files for matches
        for file_name in files:
            file_path = os.path.join(root, file_name)
            
            try:
                # Skip excluded files
                rel_path = os.path.relpath(file_path, validated_path)
                should_exclude = any(
                    fnmatch.fnmatch(rel_path, '*/' + pat + '/*') if '*' not in pat else fnmatch.fnmatch(rel_path, pat)
                    for pat in excludePatterns
                )
                
                if should_exclude:
                    continue
                    
                # Check if the file name contains the pattern
                if pattern.lower() in file_name.lower():
                    results.append(file_path)
            except Exception:
                # Skip any files that fail validation
                continue
    
    return "\n".join(results) if results else "No matches found"


@mcp.tool()
def get_file_info(path: str) -> str:
    """
    Retrieve detailed metadata about a file or directory. Returns comprehensive
    information including size, creation time, last modified time, permissions,
    and type. This tool is perfect for understanding file characteristics
    without reading the actual content. Only works within allowed directories.
    """
    validated_path = validate_path(path)
    info = get_file_stats(validated_path)
    
    return "\n".join(f"{key}: {value}" for key, value in info.items())

@mcp.tool()
def list_allowed_directories() -> str:
    """
    Returns the list of directories that this server is allowed to access.
    Use this to understand which directories are available before trying to access files.
    """
    return f"Allowed directories:\n{chr(10).join(allowed_directories)}"


# Add a dynamic greeting resource
@mcp.resource("greeting://{name}")
def get_greeting(name: str) -> str:
    """Get a personalized greeting"""
    return f"Hello, {name}!"
    
if __name__ == "__main__":
    print(f"Secure MCP Filesystem Server running", file=sys.stderr)
    print(f"Allowed directories: {allowed_directories}", file=sys.stderr)
    mcp.run()
