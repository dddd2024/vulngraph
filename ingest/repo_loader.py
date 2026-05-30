"""
Repository loader for loading code from various sources.

Supports loading code snippets and local repositories.
"""

from pathlib import Path
from audit_core.models import CodeUnit
from ingest.code_unit_builder import build_code_unit_from_file, build_code_unit_from_snippet
from ingest.language_router import is_supported_file


# Directories to ignore when scanning repositories
IGNORED_DIRS = {
    ".git",
    "node_modules",
    "dist",
    "build",
    "__pycache__",
    ".venv",
    "venv",
    "target",
    ".idea",
    ".vscode",
    ".settings",
    "vendor",
    "third_party",
    ".pytest_cache",
    ".mypy_cache",
    ".tox",
    "*.egg-info",
}


class RepoLoader:
    """
    Loader for code from various sources.
    
    Supports:
    - Code snippets (direct code input)
    - Local repository paths
    - GitHub repository URLs (TODO: placeholder for future implementation)
    """
    
    def load_code_snippet(self, code: str, language_hint: str | None = None) -> list[CodeUnit]:
        """
        Load a code snippet as a CodeUnit.
        
        Args:
            code: The code snippet to load
            language_hint: Optional language hint (e.g., "python", "javascript")
            
        Returns:
            List containing a single CodeUnit
        """
        unit = build_code_unit_from_snippet(code, language_hint)
        return [unit]
    
    def load_local_repo(self, repo_path: str) -> list[CodeUnit]:
        """
        Load all supported files from a local repository.
        
        Args:
            repo_path: Path to the local repository
            
        Returns:
            List of CodeUnits for all supported files
            
        Raises:
            FileNotFoundError: If the repository path doesn't exist
            NotADirectoryError: If the path is not a directory
        """
        repo_path = Path(repo_path)
        
        if not repo_path.exists():
            raise FileNotFoundError(f"Repository path not found: {repo_path}")
        
        if not repo_path.is_dir():
            raise NotADirectoryError(f"Path is not a directory: {repo_path}")
        
        code_units = []
        
        for file_path in self._scan_directory(repo_path):
            try:
                unit = build_code_unit_from_file(file_path, root=repo_path)
                code_units.append(unit)
            except (UnicodeDecodeError, IOError):
                # Skip files that can't be read as text
                continue
        
        return code_units
    
    def load_github_repo(self, repo_url: str) -> list[CodeUnit]:
        """
        Load a GitHub repository.
        
        Args:
            repo_url: GitHub repository URL
            
        Returns:
            List of CodeUnits (currently returns empty list as placeholder)
            
        TODO: Implement GitHub repository cloning and loading
        """
        # TODO: Implement GitHub repo loading
        # For now, return empty list to avoid crashing
        return []
    
    def _scan_directory(self, root: Path) -> list[Path]:
        """
        Scan a directory for supported code files.
        
        Args:
            root: Root directory to scan
            
        Returns:
            List of paths to supported files
        """
        files = []
        
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            
            # Check if any parent directory should be ignored
            if any(part in IGNORED_DIRS for part in path.relative_to(root).parts[:-1]):
                continue
            
            # Check if file has supported extension
            if is_supported_file(str(path)):
                files.append(path)
        
        return sorted(files)
    
    def _should_ignore(self, path: Path, root: Path) -> bool:
        """
        Check if a path should be ignored.
        
        Args:
            path: Path to check
            root: Root directory
            
        Returns:
            True if the path should be ignored
        """
        relative = path.relative_to(root)
        return any(part in IGNORED_DIRS for part in relative.parts)
