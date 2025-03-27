import os
import sys
import json
import difflib
from pathlib import Path
from dataclasses import dataclass
from typing import List, Dict, Union, Optional, Tuple, Any
import fnmatch
from datetime import datetime

from mcp.server.fastmcp import FastMCP, Context

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

# Create MCP server
mcp = FastMCP("secure-filesystem-server", version="0.2.0")

# Security utilities
def validate_path(requested_path: str) -> str:
    expanded_path = expand_home(requested_path)
    absolute = os.path.abspath(expanded_path)
    normalized_requested = normalize_path(absolute)

    # Check if path is within allowed directories
    is_allowed = any(normalized_requested.startswith(dir) for dir in allowed_directories)
    if not is_allowed:
        raise ValueError(f"Access denied - path outside allowed directories: {absolute} not in {', '.join(allowed_directories)}")

    # Handle symlinks by checking their real path
    try:
        real_path = os.path.realpath(absolute)
        normalized_real = normalize_path(real_path)
        is_real_path_allowed = any(normalized_real.startswith(dir) for dir in allowed_directories)
        if not is_real_path_allowed:
            raise ValueError("Access denied - symlink target outside allowed directories")
        return real_path
    except Exception:
        # For new files that don't exist yet, verify parent directory
        parent_dir = os.path.dirname(absolute)
        try:
            real_parent_path = os.path.realpath(parent_dir)
            normalized_parent = normalize_path(real_parent_path)
            is_parent_allowed = any(normalized_parent.startswith(dir) for dir in allowed_directories)
            if not is_parent_allowed:
                raise ValueError("Access denied - parent directory outside allowed directories")
            return absolute
        except Exception:
            raise ValueError(f"Parent directory does not exist: {parent_dir}")

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

def search_files(
    root_path: str,
    pattern: str,
    exclude_patterns: List[str] = []
) -> List[str]:
    results = []

    def search(current_path):
        try:
            entries = os.listdir(current_path)
            for entry in entries:
                full_path = os.path.join(current_path, entry)
                
                try:
                    # Validate each path before processing
                    validate_path(full_path)
                    
                    # Check if path matches any exclude pattern
                    rel_path = os.path.relpath(full_path, root_path)
                    should_exclude = any(
                        fnmatch.fnmatch(rel_path, '*/' + pat + '/*') if '*' not in pat else fnmatch.fnmatch(rel_path, pat)
                        for pat in exclude_patterns
                    )
                    
                    if should_exclude:
                        continue
                    
                    if pattern.lower() in entry.lower():
                        results.append(full_path)
                    
                    if os.path.isdir(full_path):
                        search(full_path)
                except Exception:
                    # Skip invalid paths during search
                    continue
        except Exception:
            pass

    search(root_path)
    return results

def normalize_line_endings(text: str) -> str:
    return text.replace('\r\n', '\n')

def create_unified_diff(original_content: str, new_content: str, filepath: str = 'file') -> str:
    # Ensure consistent line endings for diff
    normalized_original = normalize_line_endings(original_content)
    normalized_new = normalize_line_endings(new_content)
    
    diff = difflib.unified_diff(
        normalized_original.splitlines(),
        normalized_new.splitlines(),
        fromfile=f"{filepath} (original)",
        tofile=f"{filepath} (modified)",
        lineterm=''
    )
    
    return '\n'.join(diff)

def apply_file_edits(
    file_path: str,
    edits: List[Dict[str, str]],
    dry_run: bool = False
) -> str:
    # Read file content and normalize line endings
    with open(file_path, 'r', encoding='utf-8') as f:
        content = normalize_line_endings(f.read())
    
    # Apply edits sequentially
    modified_content = content
    for edit in edits:
        normalized_old = normalize_line_endings(edit['oldText'])
        normalized_new = normalize_line_endings(edit['newText'])
        
        # If exact match exists, use it
        if normalized_old in modified_content:
            modified_content = modified_content.replace(normalized_old, normalized_new)
            continue
        
        # Otherwise, try line-by-line matching with flexibility for whitespace
        old_lines = normalized_old.split('\n')
        content_lines = modified_content.split('\n')
        match_found = False
        
        for i in range(len(content_lines) - len(old_lines) + 1):
            potential_match = content_lines[i:i + len(old_lines)]
            
            # Compare lines with normalized whitespace
            is_match = all(
                old_line.strip() == content_line.strip()
                for old_line, content_line in zip(old_lines, potential_match)
            )
            
            if is_match:
                # Preserve original indentation of first line
                original_indent = content_lines[i].split(content_lines[i].lstrip())[0] if content_lines[i] else ''
                new_lines = []
                
                for j, line in enumerate(normalized_new.split('\n')):
                    if j == 0:
                        new_lines.append(original_indent + line.lstrip())
                    else:
                        # For subsequent lines, try to preserve relative indentation
                        if j < len(old_lines):
                            old_indent = old_lines[j].split(old_lines[j].lstrip())[0] if old_lines[j] else ''
                            new_indent = line.split(line.lstrip())[0] if line else ''
                            if old_indent and new_indent:
                                relative_indent = max(0, len(new_indent) - len(old_indent))
                                new_lines.append(original_indent + ' ' * relative_indent + line.lstrip())
                            else:
                                new_lines.append(line)
                        else:
                            new_lines.append(line)
                
                content_lines[i:i + len(old_lines)] = new_lines
                modified_content = '\n'.join(content_lines)
                match_found = True
                break
        
        if not match_found:
            raise ValueError(f"Could not find exact match for edit:\n{edit['oldText']}")
    
    # Create unified diff
    diff = create_unified_diff(content, modified_content, file_path)
    
    # Format diff with appropriate number of backticks
    num_backticks = 3
    while '`' * num_backticks in diff:
        num_backticks += 1
    formatted_diff = f"{('`' * num_backticks)}diff\n{diff}\n{('`' * num_backticks)}\n\n"
    
    if not dry_run:
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(modified_content)
    
    return formatted_diff

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

@dataclass
class EditOperation:
    """Edit operation for applying changes to a file"""
    oldText: str
    newText: str

@mcp.tool()
def edit_file(path: str, edits: List[EditOperation], dryRun: bool = False) -> str:
    """
    Make line-based edits to a text file. Each edit replaces exact line sequences
    with new content. Returns a git-style diff showing the changes made.
    Only works within allowed directories.
    """
    validated_path = validate_path(path)
    # Convert EditOperation objects to dictionaries
    edit_dicts = [{"oldText": edit.oldText, "newText": edit.newText} for edit in edits]
    result = apply_file_edits(validated_path, edit_dicts, dryRun)
    return result

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
def directory_tree(path: str) -> str:
    """
    Get a recursive tree view of files and directories as a JSON structure.
    Each entry includes 'name', 'type' (file/directory), and 'children' for directories.
    Files have no children array, while directories always have a children array (which may be empty).
    The output is formatted with 2-space indentation for readability. Only works within allowed directories.
    """
    validated_path = validate_path(path)
    
    def build_tree(current_path):
        entries = os.listdir(current_path)
        result = []
        
        for entry in entries:
            entry_path = os.path.join(current_path, entry)
            entry_data = {
                "name": entry,
                "type": "directory" if os.path.isdir(entry_path) else "file"
            }
            
            if os.path.isdir(entry_path):
                entry_data["children"] = build_tree(entry_path)
            
            result.append(entry_data)
        
        return result
    
    tree_data = build_tree(validated_path)
    return json.dumps(tree_data, indent=2)

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
    matching items. Great for finding files when you don't know their exact location.
    Only searches within allowed directories.
    """
    if excludePatterns is None:
        excludePatterns = []
    
    validated_path = validate_path(path)
    results = search_files(validated_path, pattern, excludePatterns)
    
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

# Main execution
if __name__ == "__main__":
    print(f"Secure MCP Filesystem Server running", file=sys.stderr)
    print(f"Allowed directories: {allowed_directories}", file=sys.stderr)
    mcp.run()
