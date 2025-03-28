# Filesystem MCP Server

A Python server implementing Model Context Protocol (MCP) for secure filesystem operations.

## Features

- Read/write files
- Create/list directories
- Move files/directories
- Search files
- Diff edits
- Get file metadata
- Git-aware directory tree listing
- Function/keyword search in files

**Note**: The server only allows operations within directories specified via command-line arguments.

## Installation

Build the Docker image locally:

```bash
docker build -t mcp/filesystem .
```

## Usage with Claude

Add this to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--mount", "type=bind,src=/path/to/your/directory,dst=/projects",
        "mcp/filesystem",
        "/projects"
      ]
    }
  }
}
```

Note: All directories are mounted to `/projects` by default. Adding the `,ro` flag will make the directory read-only.

## Available Tools

### read_file
- Read complete contents of a file
- Input: `path` (string)

### read_multiple_files
- Read multiple files simultaneously
- Input: `paths` (string[])
- Failed reads won't stop the entire operation

### read_file_by_line
- Read specific lines or line ranges from a file
- Inputs:
  - `path` (string)
  - `ranges` (string[]): Line numbers or ranges (e.g., ["5", "10-20"])

### read_file_by_keyword
- Find lines containing a keyword with optional context
- Inputs:
  - `path` (string)
  - `keyword` (string): Text to search for
  - `before` (int): Lines to include before match (default: 0)
  - `after` (int): Lines to include after match (default: 0)
  - `use_regex` (bool): Use regex pattern (default: false)
  - `ignore_case` (bool): Case-insensitive search (default: false)

### read_function_by_keyword
- Extract function definitions by keyword
- Inputs:
  - `path` (string)
  - `keyword` (string): Typically function name
  - `before` (int): Lines to include before match (default: 0)
  - `use_regex` (bool): Use regex pattern (default: false)

### write_file
- Create or overwrite a file
- Inputs:
  - `path` (string)
  - `content` (string)

### edit_file
- Make surgical edits to a file
- Inputs:
  - `path` (string)
  - `edits` (array): List of edit operations
    - `oldText` (string): Text to search for
    - `newText` (string): Text to replace with
  - `dryRun` (boolean): Preview changes without applying (default: false)
- Returns a unified diff showing changes

### create_directory
- Create directory or ensure it exists
- Input: `path` (string)
- Creates parent directories if needed

### list_directory
- List directory contents with [FILE] or [DIR] prefixes
- Input: `path` (string)

### directory_tree
- Get a recursive tree view of files and directories
- Inputs:
  - `path` (string)
  - `count_lines` (boolean): Include line counts (default: false)

### git_directory_tree
- Get a directory tree for a git repository respecting .gitignore
- Inputs:
  - `path` (string)
  - `count_lines` (boolean): Include line counts (default: false)

### move_file
- Move or rename files and directories
- Inputs:
  - `source` (string)
  - `destination` (string)

### search_files
- Recursively search for files/directories matching a pattern
- Inputs:
  - `path` (string): Starting directory
  - `pattern` (string): Search pattern
  - `excludePatterns` (string[]): Glob patterns to exclude

### get_file_info
- Get detailed file metadata
- Input: `path` (string)
- Returns size, creation time, modified time, permissions, etc.

### list_allowed_directories
- List all directories the server is allowed to access

## Security

The server maintains a whitelist of allowed directories and performs strict path validation to prevent unauthorized access. Symlink targets are validated to ensure they don't escape the allowed directories.

## Requirements

- Python 3.12+
- MCP 1.5.0+
- Docker

## License

[MIT](LICENSE)
