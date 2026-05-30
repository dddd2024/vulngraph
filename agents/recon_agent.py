"""
Reconnaissance agent for initial code inspection.

The ReconAgent performs initial analysis of code units to identify
potential attack surfaces and areas of interest for further analysis.
"""

import re
from audit_core.models import CodeUnit, AgentHypothesis, AgentLog
from agents.base_agent import BaseAgent


class ReconAgent(BaseAgent):
    """
    Agent that performs initial reconnaissance on code.
    
    Extracts lightweight attack surface information from CodeUnits:
    - Web routes (HTTP endpoints)
    - Request parameters (user input sources)
    - File operations (read/write)
    - SQL operations (database queries)
    - Command execution (system calls)
    - Deserialization (object loading)
    
    Does NOT read files directly - only analyzes CodeUnit content.
    Does NOT call analyzers - only identifies patterns.
    """
    
    name = "recon"
    
    # Pattern definitions for attack surface detection
    ROUTE_PATTERNS = {
        "python": [
            r'@app\.route\s*\(\s*["\']([^"\']+)["\']',
            r'@app\.get\s*\(\s*["\']([^"\']+)["\']',
            r'@app\.post\s*\(\s*["\']([^"\']+)["\']',
            r'@router\.route\s*\(\s*["\']([^"\']+)["\']',
            r'@router\.get\s*\(\s*["\']([^"\']+)["\']',
            r'@router\.post\s*\(\s*["\']([^"\']+)["\']',
        ],
        "javascript": [
            r'app\.get\s*\(\s*["\']([^"\']+)["\']',
            r'app\.post\s*\(\s*["\']([^"\']+)["\']',
            r'router\.get\s*\(\s*["\']([^"\']+)["\']',
            r'router\.post\s*\(\s*["\']([^"\']+)["\']',
        ],
        "java": [
            r'@RequestMapping\s*\(\s*["\']([^"\']+)["\']',
            r'@GetMapping\s*\(\s*["\']([^"\']+)["\']',
            r'@PostMapping\s*\(\s*["\']([^"\']+)["\']',
            r'@RequestMapping\s*\(\s*value\s*=\s*["\']([^"\']+)["\']',
        ],
    }
    
    REQUEST_PATTERNS = {
        "python": [
            r'request\.args\.get\s*\(\s*["\']([^"\']+)["\']',
            r'request\.form\.get\s*\(\s*["\']([^"\']+)["\']',
            r'request\.values\.get\s*\(\s*["\']([^"\']+)["\']',
            r'request\.get_json\s*\(\s*\)',
            r'request\.data',
            r'request\.GET\.get\s*\(\s*["\']([^"\']+)["\']',
            r'request\.POST\.get\s*\(\s*["\']([^"\']+)["\']',
        ],
        "javascript": [
            r'req\.query\.([a-zA-Z_][a-zA-Z0-9_]*)',
            r'req\.body\.([a-zA-Z_][a-zA-Z0-9_]*)',
            r'req\.params\.([a-zA-Z_][a-zA-Z0-9_]*)',
            r'request\.query\.([a-zA-Z_][a-zA-Z0-9_]*)',
            r'request\.body\.([a-zA-Z_][a-zA-Z0-9_]*)',
        ],
        "java": [
            r'request\.getParameter\s*\(\s*["\']([^"\']+)["\']',
            r'@RequestParam\s*\(\s*["\']([^"\']+)["\']',
            r'@PathVariable\s*\(\s*["\']([^"\']+)["\']',
            r'HttpServletRequest',
        ],
    }
    
    FILE_PATTERNS = {
        "python": [
            r'open\s*\(\s*([^,\)]+)',
            r'Path\s*\(\s*([^,\)]+)',
            r'\.read\s*\(\s*\)',
            r'\.write\s*\(\s*',
            r'shutil\.copy\s*\(\s*',
            r'shutil\.move\s*\(\s*',
        ],
        "javascript": [
            r'fs\.readFile\s*\(\s*',
            r'fs\.writeFile\s*\(\s*',
            r'fs\.open\s*\(\s*',
            r'fs\.createReadStream\s*\(\s*',
            r'fs\.createWriteStream\s*\(\s*',
        ],
        "java": [
            r'new\s+File\s*\(\s*',
            r'FileInputStream\s*\(\s*',
            r'FileOutputStream\s*\(\s*',
            r'FileReader\s*\(\s*',
            r'FileWriter\s*\(\s*',
        ],
        "c": [
            r'fopen\s*\(\s*',
            r'open\s*\(\s*',
            r'read\s*\(\s*',
            r'write\s*\(\s*',
        ],
    }
    
    SQL_PATTERNS = {
        "python": [
            r'\.execute\s*\(\s*',
            r'\.executemany\s*\(\s*',
            r'cursor\.execute',
            r'connection\.execute',
            r'SELECT\s+',
            r'INSERT\s+',
            r'UPDATE\s+',
            r'DELETE\s+',
        ],
        "javascript": [
            r'\.query\s*\(\s*',
            r'\.execute\s*\(\s*',
            r'SELECT\s+',
            r'INSERT\s+',
        ],
        "java": [
            r'executeQuery\s*\(\s*',
            r'executeUpdate\s*\(\s*',
            r'execute\s*\(\s*',
            r'SELECT\s+',
            r'INSERT\s+',
        ],
    }
    
    COMMAND_PATTERNS = {
        "python": [
            r'os\.system\s*\(\s*',
            r'os\.popen\s*\(\s*',
            r'subprocess\.run\s*\(\s*',
            r'subprocess\.call\s*\(\s*',
            r'subprocess\.Popen\s*\(\s*',
            r'eval\s*\(\s*',
            r'exec\s*\(\s*',
        ],
        "javascript": [
            r'exec\s*\(\s*',
            r'execSync\s*\(\s*',
            r'spawn\s*\(\s*',
            r'eval\s*\(\s*',
            r'Function\s*\(\s*',
        ],
        "java": [
            r'Runtime\.getRuntime\s*\(\s*\)\s*\.\s*exec\s*\(\s*',
            r'ProcessBuilder\s*\(\s*',
        ],
        "c": [
            r'system\s*\(\s*',
            r'popen\s*\(\s*',
            r'exec[lv][pe]?\s*\(\s*',
        ],
    }
    
    DESERIALIZATION_PATTERNS = {
        "python": [
            r'pickle\.load\s*\(\s*',
            r'pickle\.loads\s*\(\s*',
            r'marshal\.load\s*\(\s*',
            r'yaml\.load\s*\(\s*',
        ],
        "java": [
            r'ObjectInputStream\s*\(\s*',
            r'readObject\s*\(\s*\)',
            r'XMLDecoder\s*\(\s*',
        ],
        "javascript": [
            r'JSON\.parse\s*\(\s*',  # Less dangerous but worth noting
        ],
    }
    
    def run(self, code_units: list[CodeUnit]) -> tuple[list[AgentHypothesis], list[AgentLog]]:
        """
        Run reconnaissance on code units.
        
        Args:
            code_units: List of code units to inspect
            
        Returns:
            Tuple of (hypotheses, logs)
        """
        hypotheses: list[AgentHypothesis] = []
        logs: list[AgentLog] = []
        
        attack_surfaces: dict[str, list[dict]] = {}
        
        for unit in code_units:
            surfaces = self._extract_attack_surfaces(unit)
            attack_surfaces[unit.path] = surfaces
            
            # Generate hypotheses for significant attack surfaces
            if surfaces:
                hypothesis = AgentHypothesis(
                    agent_name=self.name,
                    hypothesis=f"Attack surfaces identified in {unit.path}",
                    vulnerability_type="Attack Surface",
                    reasoning_summary=self._summarize_surfaces(surfaces),
                    confidence="medium",
                    supporting_evidence_ids=[unit.id],
                    metadata={
                        "attack_surfaces": surfaces,
                        "language": unit.language,
                    }
                )
                hypotheses.append(hypothesis)
        
        # Log reconnaissance activity
        log = AgentLog(
            agent_name=self.name,
            stage="recon",
            message=f"ReconAgent analyzed {len(code_units)} code units, found {len(hypotheses)} with attack surfaces.",
            input_refs=[unit.id for unit in code_units],
            output_refs=[h.id for h in hypotheses],
            metadata={
                "total_attack_surfaces": sum(len(s) for s in attack_surfaces.values()),
                "files_with_surfaces": len(hypotheses),
            }
        )
        logs.append(log)
        
        return hypotheses, logs
    
    def _extract_attack_surfaces(self, unit: CodeUnit) -> list[dict]:
        """
        Extract attack surfaces from a code unit.
        
        Args:
            unit: Code unit to analyze
            
        Returns:
            List of attack surface dictionaries
        """
        surfaces: list[dict] = []
        content = unit.content
        language = unit.language
        
        # Extract routes
        routes = self._find_patterns(content, language, self.ROUTE_PATTERNS, "route")
        for route in routes:
            surfaces.append({
                "type": "route",
                "value": route["match"],
                "line": route["line"],
                "risk": "medium",
            })
        
        # Extract request parameters
        requests = self._find_patterns(content, language, self.REQUEST_PATTERNS, "request")
        for req in requests:
            surfaces.append({
                "type": "request",
                "value": req["match"],
                "line": req["line"],
                "risk": "high",
            })
        
        # Extract file operations
        files = self._find_patterns(content, language, self.FILE_PATTERNS, "file")
        for file_op in files:
            surfaces.append({
                "type": "file",
                "value": file_op["match"],
                "line": file_op["line"],
                "risk": "medium",
            })
        
        # Extract SQL operations
        sqls = self._find_patterns(content, language, self.SQL_PATTERNS, "sql")
        for sql in sqls:
            surfaces.append({
                "type": "sql",
                "value": sql["match"],
                "line": sql["line"],
                "risk": "high",
            })
        
        # Extract command execution
        commands = self._find_patterns(content, language, self.COMMAND_PATTERNS, "command")
        for cmd in commands:
            surfaces.append({
                "type": "command",
                "value": cmd["match"],
                "line": cmd["line"],
                "risk": "critical",
            })
        
        # Extract deserialization
        desers = self._find_patterns(content, language, self.DESERIALIZATION_PATTERNS, "deserialization")
        for deser in desers:
            surfaces.append({
                "type": "deserialization",
                "value": deser["match"],
                "line": deser["line"],
                "risk": "critical",
            })
        
        return surfaces
    
    def _find_patterns(
        self,
        content: str,
        language: str,
        pattern_dict: dict,
        category: str
    ) -> list[dict]:
        """
        Find all matches for patterns in content.
        
        Args:
            content: Code content
            language: Programming language
            pattern_dict: Dictionary of patterns by language
            category: Pattern category name
            
        Returns:
            List of match dictionaries with 'match' and 'line' keys
        """
        matches: list[dict] = []
        patterns = pattern_dict.get(language, [])
        
        lines = content.split("\n")
        for i, line in enumerate(lines, start=1):
            for pattern in patterns:
                try:
                    for m in re.finditer(pattern, line, re.IGNORECASE):
                        matches.append({
                            "match": m.group(1) if m.groups() else m.group(0),
                            "line": i,
                            "category": category,
                        })
                except re.error:
                    continue
        
        return matches
    
    def _summarize_surfaces(self, surfaces: list[dict]) -> str:
        """
        Summarize attack surfaces for hypothesis reasoning.
        
        Args:
            surfaces: List of attack surface dictionaries
            
        Returns:
            Summary string
        """
        if not surfaces:
            return "No attack surfaces identified."
        
        # Count by type
        type_counts: dict[str, int] = {}
        for surface in surfaces:
            type_counts[surface["type"]] = type_counts.get(surface["type"], 0) + 1
        
        # Build summary
        parts = []
        for type_name, count in sorted(type_counts.items(), key=lambda x: -x[1]):
            parts.append(f"{count} {type_name} operations")
        
        return f"Identified: {', '.join(parts)}. These entry points may require security review."