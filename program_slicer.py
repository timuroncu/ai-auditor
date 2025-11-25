"""
AST-based Program Slicer for Security Analysis

This module builds dataflow-aware program slices to provide rich context
for LLM-based vulnerability analysis, going beyond simple line ranges.
"""

import ast
import os
from typing import Dict, List, Set, Tuple, Optional
from dataclasses import dataclass


@dataclass
class ProgramSlice:
    """Structured representation of a program slice for a security finding"""
    sink_context: str  # Full function containing the sink
    upstream_dataflow: str  # Variable definitions and transformations
    helpers_and_sanitizers: str  # Helper/validator functions
    callers_and_entrypoints: str  # Optional: callers in the same file
    metadata: Dict  # Additional info about the slice
    

class PythonSlicer:
    """AST-based slicer for Python code"""
    
    def __init__(self, source_code: str, file_path: str):
        self.source_code = source_code
        self.file_path = file_path
        self.lines = source_code.split('\n')
        try:
            self.tree = ast.parse(source_code)
        except SyntaxError as e:
            print(f"  Warning: Syntax error parsing {file_path}: {e}")
            self.tree = None
        
        # Track all function definitions for helper lookup
        self.function_defs = {}  # name -> ast.FunctionDef
        self.class_defs = {}  # name -> ast.ClassDef
        if self.tree:
            self._index_definitions()
    
    def _index_definitions(self):
        """Build an index of all function and class definitions"""
        for node in ast.walk(self.tree):
            if isinstance(node, ast.FunctionDef):
                self.function_defs[node.name] = node
            elif isinstance(node, ast.ClassDef):
                self.class_defs[node.name] = node
    
    def build_slice(
        self, 
        sink_line: int, 
        suspicious_vars: List[str],
        max_lines: int = 600
    ) -> ProgramSlice:
        """
        Build a dataflow-aware program slice for a security sink
        
        Args:
            sink_line: Line number of the security sink (1-based)
            suspicious_vars: Variables involved in the vulnerability
            max_lines: Maximum total lines to include in the slice
        
        Returns:
            ProgramSlice with structured code sections
        """
        if not self.tree:
            return self._fallback_slice(sink_line, max_lines)
        
        # Find the function containing the sink
        sink_function = self._find_containing_function(sink_line)
        
        if not sink_function:
            return self._fallback_slice(sink_line, max_lines)
        
        # Build each section of the slice
        metadata = {
            "sink_line": sink_line,
            "sink_function": sink_function.name if sink_function else "unknown",
            "suspicious_vars": suspicious_vars,
            "used_fallback": False
        }
        
        # Section 1: Sink context (full containing function)
        sink_context = self._extract_function_code(sink_function, sink_line)
        
        # Section 2: Upstream dataflow (variable definitions)
        upstream_dataflow = self._extract_upstream_dataflow(
            sink_function, sink_line, suspicious_vars
        )
        
        # Section 3: Helpers and sanitizers
        helpers_and_sanitizers = self._extract_helper_functions(
            sink_function, suspicious_vars
        )
        
        # Section 4: Callers (limited to keep size manageable)
        callers_and_entrypoints = self._extract_callers(
            sink_function.name, max_callers=2
        )
        
        # Check total size and prioritize if needed
        total_lines = (
            len(sink_context.split('\n')) +
            len(upstream_dataflow.split('\n')) +
            len(helpers_and_sanitizers.split('\n')) +
            len(callers_and_entrypoints.split('\n'))
        )
        
        if total_lines > max_lines:
            # Prioritize: sink_context > upstream > helpers > callers
            callers_and_entrypoints = "[Omitted to stay within size limit]"
            
            if len(sink_context.split('\n')) + len(upstream_dataflow.split('\n')) > max_lines * 0.7:
                helpers_and_sanitizers = "[Omitted to stay within size limit]"
        
        metadata["total_slice_lines"] = total_lines
        metadata["truncated"] = total_lines > max_lines
        
        return ProgramSlice(
            sink_context=sink_context,
            upstream_dataflow=upstream_dataflow,
            helpers_and_sanitizers=helpers_and_sanitizers,
            callers_and_entrypoints=callers_and_entrypoints,
            metadata=metadata
        )
    
    def _find_containing_function(self, line_num: int) -> Optional[ast.FunctionDef]:
        """Find the function that contains the given line number"""
        for node in ast.walk(self.tree):
            if isinstance(node, ast.FunctionDef):
                if hasattr(node, 'lineno') and hasattr(node, 'end_lineno'):
                    if node.lineno <= line_num <= (node.end_lineno or node.lineno):
                        return node
        return None
    
    def _extract_function_code(self, func_node: ast.FunctionDef, highlight_line: int) -> str:
        """Extract the full code of a function with the sink line highlighted"""
        if not hasattr(func_node, 'lineno') or not hasattr(func_node, 'end_lineno'):
            return "[Unable to extract function code]"
        
        start_line = func_node.lineno - 1  # Convert to 0-based
        end_line = func_node.end_lineno or start_line + 1
        
        # Include decorator lines if present
        if func_node.decorator_list and func_node.decorator_list[0].lineno:
            start_line = func_node.decorator_list[0].lineno - 1
        
        lines = []
        for i in range(start_line, min(end_line, len(self.lines))):
            line_num = i + 1
            prefix = ">>> " if line_num == highlight_line else "    "
            lines.append(f"{prefix}{line_num:4}: {self.lines[i]}")
        
        return "\n".join(lines)
    
    def _extract_upstream_dataflow(
        self, 
        func_node: ast.FunctionDef, 
        sink_line: int,
        suspicious_vars: List[str]
    ) -> str:
        """
        Extract definitions and assignments of suspicious variables
        that occur before the sink
        """
        if not suspicious_vars:
            return "[No suspicious variables identified]"
        
        definitions = []
        tracked_vars = set(suspicious_vars)
        newly_found = set(suspicious_vars)
        
        # Recursively track variable origins
        max_iterations = 3  # Limit recursion depth
        for _ in range(max_iterations):
            if not newly_found:
                break
            
            current_vars = newly_found.copy()
            newly_found = set()
            
            for node in ast.walk(func_node):
                if not hasattr(node, 'lineno') or node.lineno >= sink_line:
                    continue
                
                # Assignment statements
                if isinstance(node, ast.Assign):
                    for target in node.targets:
                        if isinstance(target, ast.Name) and target.id in current_vars:
                            # Found a definition of a tracked variable
                            def_line = node.lineno - 1
                            definitions.append((node.lineno, self.lines[def_line]))
                            
                            # Track variables used in the assignment RHS
                            for rhs_node in ast.walk(node.value):
                                if isinstance(rhs_node, ast.Name):
                                    if rhs_node.id not in tracked_vars:
                                        newly_found.add(rhs_node.id)
                                        tracked_vars.add(rhs_node.id)
                
                # AugAssign (+=, -=, etc.)
                elif isinstance(node, ast.AugAssign):
                    if isinstance(node.target, ast.Name) and node.target.id in current_vars:
                        def_line = node.lineno - 1
                        definitions.append((node.lineno, self.lines[def_line]))
                
                # Function parameters
                elif isinstance(node, ast.FunctionDef):
                    for arg in node.args.args:
                        if arg.arg in current_vars:
                            # Include function signature
                            sig_line = node.lineno - 1
                            definitions.append((node.lineno, f"# Parameter: {arg.arg}"))
                            definitions.append((node.lineno, self.lines[sig_line]))
        
        # Sort by line number and format
        definitions.sort(key=lambda x: x[0])
        
        if not definitions:
            return f"[No definitions found for variables: {', '.join(suspicious_vars)}]"
        
        result_lines = []
        for line_num, line_content in definitions:
            result_lines.append(f"    {line_num:4}: {line_content}")
        
        return "\n".join(result_lines)
    
    def _extract_helper_functions(
        self,
        sink_func: ast.FunctionDef,
        suspicious_vars: List[str]
    ) -> str:
        """
        Find and extract helper/sanitizer/validator functions that operate
        on the suspicious data
        """
        helper_functions = set()
        
        # Look for function calls in the sink function that might be sanitizers
        for node in ast.walk(sink_func):
            if isinstance(node, ast.Call):
                # Get the function name
                func_name = None
                if isinstance(node.func, ast.Name):
                    func_name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    func_name = node.func.attr
                
                if func_name:
                    # Check if this function might be relevant
                    # Look for common patterns: validate, sanitize, clean, escape, check, etc.
                    relevant_keywords = [
                        'validate', 'sanitize', 'clean', 'escape', 'check',
                        'safe', 'secure', 'filter', 'strip', 'normalize'
                    ]
                    
                    if any(keyword in func_name.lower() for keyword in relevant_keywords):
                        helper_functions.add(func_name)
                    
                    # Also check if any suspicious var is passed to this function
                    for arg in node.args:
                        if isinstance(arg, ast.Name) and arg.id in suspicious_vars:
                            helper_functions.add(func_name)
        
        # Extract the code for these helper functions
        extracted_helpers = []
        for func_name in helper_functions:
            if func_name in self.function_defs:
                helper_node = self.function_defs[func_name]
                helper_code = self._extract_function_code(helper_node, -1)
                extracted_helpers.append(f"\n# Helper function: {func_name}\n{helper_code}")
        
        if not extracted_helpers:
            return "[No helper/sanitizer functions detected]"
        
        return "\n".join(extracted_helpers)
    
    def _extract_callers(self, function_name: str, max_callers: int = 2) -> str:
        """
        Find functions that call the function containing the sink
        """
        callers = []
        
        for func_name, func_node in self.function_defs.items():
            if func_name == function_name:
                continue
            
            # Check if this function calls our target function
            for node in ast.walk(func_node):
                if isinstance(node, ast.Call):
                    called_name = None
                    if isinstance(node.func, ast.Name):
                        called_name = node.func.id
                    elif isinstance(node.func, ast.Attribute):
                        called_name = node.func.attr
                    
                    if called_name == function_name:
                        # Found a caller
                        caller_code = self._extract_function_code(func_node, -1)
                        callers.append(f"\n# Caller: {func_name}\n{caller_code}")
                        break
            
            if len(callers) >= max_callers:
                break
        
        if not callers:
            return "[No callers found in the same file]"
        
        return "\n".join(callers)
    
    def _fallback_slice(self, sink_line: int, max_lines: int) -> ProgramSlice:
        """Fallback to simple line-based extraction when AST parsing fails"""
        # Extract first 100 lines + context around sink
        header_lines = min(100, len(self.lines))
        header = "\n".join([f"    {i+1:4}: {self.lines[i]}" for i in range(header_lines)])
        
        if sink_line <= header_lines:
            sink_context = "[Sink is in header section above]"
        else:
            # Extract ±50 lines around sink
            start = max(header_lines, sink_line - 50)
            end = min(len(self.lines), sink_line + 50)
            context_lines = []
            for i in range(start, end):
                line_num = i + 1
                prefix = ">>> " if line_num == sink_line else "    "
                context_lines.append(f"{prefix}{line_num:4}: {self.lines[i]}")
            sink_context = "\n".join(context_lines)
        
        return ProgramSlice(
            sink_context=f"[Header]\n{header}\n\n[Sink Context]\n{sink_context}",
            upstream_dataflow="[Fallback mode - AST analysis unavailable]",
            helpers_and_sanitizers="[Fallback mode - AST analysis unavailable]",
            callers_and_entrypoints="[Fallback mode - AST analysis unavailable]",
            metadata={"used_fallback": True, "reason": "AST parsing failed"}
        )


def detect_language(file_path: str) -> str:
    """Detect programming language from file extension"""
    ext = os.path.splitext(file_path)[1].lower()
    lang_map = {
        '.py': 'python',
        '.js': 'javascript',
        '.ts': 'typescript',
        '.java': 'java',
        '.go': 'go',
        '.rb': 'ruby',
        '.php': 'php',
        '.cs': 'csharp',
    }
    return lang_map.get(ext, 'unknown')


def build_program_slice(
    file_content: str,
    file_path: str,
    sink_line: int,
    semgrep_dataflow: Dict = None,
    max_lines: int = 600
) -> Optional[ProgramSlice]:
    """
    Main entry point: Build a program slice for a security finding
    
    Args:
        file_content: Full source code content
        file_path: Path to the source file
        sink_line: Line number where the vulnerability occurs
        semgrep_dataflow: Optional dataflow trace from Semgrep
        max_lines: Maximum lines to include in slice
    
    Returns:
        ProgramSlice or None if slicing fails
    """
    language = detect_language(file_path)
    
    # Extract suspicious variables from Semgrep's dataflow trace
    suspicious_vars = []
    if semgrep_dataflow:
        # Extract intermediate variable names
        intermediate_vars = semgrep_dataflow.get('intermediate_vars', [])
        for var in intermediate_vars:
            var_name = var.get('content', '')
            if var_name and var_name not in suspicious_vars:
                suspicious_vars.append(var_name)
    
    try:
        if language == 'python':
            slicer = PythonSlicer(file_content, file_path)
            return slicer.build_slice(sink_line, suspicious_vars, max_lines)
        else:
            # For other languages, fall back to simple extraction
            print(f"  Info: AST slicing not yet supported for {language}, using fallback")
            slicer = PythonSlicer(file_content, file_path)
            return slicer._fallback_slice(sink_line, max_lines)
    
    except Exception as e:
        print(f"  Warning: Program slicing failed: {e}")
        return None

