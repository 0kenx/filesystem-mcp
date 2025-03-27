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

# Directory tree formatting function
def format_directory_tree(root_path, root_name, include_files=None, count_lines=False):
    """
    Common helper function to format a directory tree in plaintext.
    
    Args:
        root_path: The base path to start the tree from
        root_name: The name to display for the root node
        include_files: Function that determines if a file should be included (None = include all)
        count_lines: Whether to include line count for files
    
    Returns:
        A formatted string representation of the directory tree
    """
    lines = [root_name]
    
    def format_tree(current_path, prefix=""):
        # Get and sort entries
        try:
            entries = sorted(os.listdir(current_path))
        except PermissionError:
            return [f"{prefix}├── Error: Permission denied"]
        except Exception as e:
            return [f"{prefix}├── Error: {str(e)}"]
            
        result = []
        
        for i, entry in enumerate(entries):
            entry_path = os.path.join(current_path, entry)
            is_last = (i == len(entries) - 1)
            
            # Check if we should include this file
            if include_files is not None and not os.path.isdir(entry_path):
                if not include_files(os.path.relpath(entry_path, root_path)):
                    continue
            
            # Add the current entry with proper prefix
            connector = "└── " if is_last else "├── "
            
            if os.path.isdir(entry_path):
                # Directory entries
                result.append(f"{prefix}{connector}{entry}/")
                
                # Process subdirectory
                child_prefix = prefix + ("    " if is_last else "│   ")
                children = format_tree(entry_path, child_prefix)
                result.extend(children)
            else:
                # File entries
                if count_lines:
                    try:
                        with open(entry_path, 'r', encoding='utf-8') as f:
                            line_count = sum(1 for _ in f)
                        result.append(f"{prefix}{connector}{entry} [{line_count} lines]")
                    except Exception:
                        # Handle binary files or other reading errors
                        result.append(f"{prefix}{connector}{entry} [binary]")
                else:
                    result.append(f"{prefix}{connector}{entry}")
        
        return result
    
    # Add all children
    lines.extend(format_tree(root_path))
    
    return "\n".join(lines)


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
def directory_tree(path: str, count_lines: bool = False) -> str:
    """
    Get a recursive tree view of files and directories in plaintext format.
    Each entry is displayed with proper indentation and tree structure.
    
    Args:
        path: Path to the directory to display
        count_lines: Whether to include the number of lines for each file (default: False)
        
    Returns:
        A plaintext tree representation of directories and files
    """
    validated_path = validate_path(path)
    
    # Get the directory name for the root node
    root_name = os.path.basename(validated_path.rstrip('/\\'))
    if not root_name:  # In case of root directory
        root_name = validated_path
    
    # Use the common formatter
    return format_directory_tree(validated_path, root_name, None, count_lines)


@mcp.tool()
def git_directory_tree(path: str, count_lines: bool = False) -> str:
    """
    Get a directory tree for a git repository in plaintext format,
    properly respecting .gitignore rules. Uses native Git commands
    to ensure correct handling of nested .gitignore files.
    
    Args:
        path: Path to the git repository directory
        count_lines: Whether to include the number of lines for each file (default: False)
        
    Returns:
        A plaintext tree representation of tracked files in the git repository
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
            # Run git ls-files to get all tracked files
            result = subprocess.run(
                [git_cmd, 'ls-files'], 
                capture_output=True, 
                text=True,
                check=True
            )
            
            git_files = set(result.stdout.strip().split('\n'))
            if not git_files or (len(git_files) == 1 and next(iter(git_files)) == ''):
                return "No tracked files found in the repository."
            
            # Define file filter function for git tracked files
            def is_git_tracked(rel_path):
                # Convert Windows path separators to Unix style for git
                rel_path = rel_path.replace('\\', '/')
                return rel_path in git_files
            
            # Get the repository name for the root node
            repo_name = os.path.basename(validated_path.rstrip('/\\'))
            if not repo_name:  # In case of root directory
                repo_name = validated_path
                
            repo_name += " (git repository)"
            
            # Use the common formatter with git file filter
            return format_directory_tree(validated_path, repo_name, is_git_tracked, count_lines)
            
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
