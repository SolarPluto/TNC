"""Static contract for the shared native Windows test harness imports.

This scan covers executable AST imports and attribute references in test modules
and ``conftest.py``. Import resolution intentionally uses pytest's live ``sys.path``:
that environment is part of the contract for bare ``_native_harness`` imports, so
an import-mode/rootdir change that makes the real consumers unresolvable must fail
here too.

Imports embedded in strings (including the diagnostic-cleanup child script) and
imports performed through importlib.import_module() or __import__() are outside its
scope and remain covered only by their runtime tests.
"""
import ast
import importlib
import importlib.util
from pathlib import Path
import tokenize


TESTS = Path(__file__).resolve().parent
NATIVE_HARNESS = '_native_harness'
POSITIVE_CONTROL = 'test_windows_appcontainer_pipe_positive_control'


def _is_type_checking(test):
    return (
        isinstance(test, ast.Name) and test.id == 'TYPE_CHECKING'
    ) or (
        isinstance(test, ast.Attribute)
        and isinstance(test.value, ast.Name)
        and test.value.id == 'typing'
        and test.attr == 'TYPE_CHECKING'
    )


class _RuntimeScan(ast.NodeVisitor):
    """Collect executable imports/attributes with their lexical scopes."""

    def __init__(self):
        self.imports = []
        self.attributes = []
        self.scope = [('module', 0)]

    def _visit_scope(self, kind, node):
        self.scope.append((kind, node.lineno))
        self.generic_visit(node)
        self.scope.pop()

    def visit_FunctionDef(self, node):
        self._visit_scope('function', node)

    def visit_AsyncFunctionDef(self, node):
        self._visit_scope('function', node)

    def visit_Lambda(self, node):
        self._visit_scope('function', node)

    def visit_ClassDef(self, node):
        self._visit_scope('class', node)

    def visit_If(self, node):
        self.visit(node.test)
        if _is_type_checking(node.test):
            for statement in node.orelse:
                self.visit(statement)
            return
        for statement in node.body:
            self.visit(statement)
        for statement in node.orelse:
            self.visit(statement)

    def visit_Import(self, node):
        self.imports.append((node, tuple(self.scope)))

    def visit_ImportFrom(self, node):
        self.imports.append((node, tuple(self.scope)))

    def visit_Attribute(self, node):
        self.attributes.append((node, tuple(self.scope)))
        self.generic_visit(node)


def _scans():
    scans = []
    scanner_errors = []
    paths = [TESTS / 'conftest.py', *sorted(TESTS.glob('test_*.py'))]
    for path in paths:
        try:
            with tokenize.open(path) as source_file:
                source = source_file.read()
            tree = ast.parse(source, filename=str(path))
        except (OSError, SyntaxError, UnicodeError) as exc:
            scanner_errors.append(f'could not parse {path.name}: {type(exc).__name__}: {exc}')
            continue
        scan = _RuntimeScan()
        scan.visit(tree)
        scans.append((path, scan))
    return scans, scanner_errors


def _assert_scanner_clean(scanner_errors):
    assert not scanner_errors, 'scanner errors:\n' + '\n'.join(scanner_errors)


def _is_harness_module(name):
    return name == NATIVE_HARNESS or name.endswith('.' + NATIVE_HARNESS)


def _find_spec(target):
    try:
        return importlib.util.find_spec(target)
    except (ImportError, ModuleNotFoundError, AttributeError, TypeError, ValueError):
        return None


def _harness_import_targets(node):
    if isinstance(node, ast.Import):
        for alias in node.names:
            if _is_harness_module(alias.name):
                yield alias.name
        return
    module = node.module or ''
    dots = '.' * node.level
    if _is_harness_module(module):
        yield dots + module
        return
    for alias in node.names:
        if alias.name == NATIVE_HARNESS:
            target = f'{module}.{alias.name}' if module else alias.name
            yield dots + target


def _harness_bindings(scan):
    aliases_by_scope = {}
    imported_names = []
    for node, scope in scan.imports:
        if isinstance(node, ast.Import):
            for alias in node.names:
                if _is_harness_module(alias.name):
                    aliases_by_scope.setdefault(scope, set()).add(alias.asname or alias.name.split('.')[0])
            continue
        module = node.module or ''
        if _is_harness_module(module):
            imported_names.extend((alias.name, node.lineno) for alias in node.names if alias.name != '*')
            continue
        for alias in node.names:
            if alias.name == NATIVE_HARNESS:
                aliases_by_scope.setdefault(scope, set()).add(alias.asname or alias.name)
    return aliases_by_scope, imported_names


def _alias_visible(alias, scope, aliases_by_scope):
    # Module bindings are visible from nested scopes. Function bindings are visible
    # in their own bodies and nested scopes. Class locals do not become lexical
    # parents of method bodies, so skip class bindings once a function is crossed.
    crossed_function = False
    for end in range(len(scope), 0, -1):
        candidate = scope[:end]
        kind = candidate[-1][0]
        if kind == 'class' and crossed_function:
            continue
        if alias in aliases_by_scope.get(candidate, ()):
            return True
        if kind == 'function':
            crossed_function = True
    return False


def _positive_control_targets(node):
    if isinstance(node, ast.Import):
        for alias in node.names:
            if alias.name == POSITIVE_CONTROL or alias.name.endswith('.' + POSITIVE_CONTROL):
                yield alias.name
        return
    module = node.module or ''
    if module == POSITIVE_CONTROL or module.endswith('.' + POSITIVE_CONTROL):
        yield module
        return
    for alias in node.names:
        if alias.name == POSITIVE_CONTROL:
            yield f'{module}.{alias.name}' if module else alias.name


def test_native_harness_import_statements_resolve():
    scans, scanner_errors = _scans()
    _assert_scanner_clean(scanner_errors)
    failures = []
    for path, scan in scans:
        for node, _scope in scan.imports:
            for target in _harness_import_targets(node):
                if _find_spec(target) is None:
                    failures.append(f'{path.name}:{node.lineno}: cannot resolve import target {target!r}')
    assert not failures, '\n'.join(failures)


def test_native_harness_referenced_names_exist():
    harness = importlib.import_module(NATIVE_HARNESS)
    scans, scanner_errors = _scans()
    _assert_scanner_clean(scanner_errors)
    failures = []
    for path, scan in scans:
        aliases_by_scope, imported_names = _harness_bindings(scan)
        for name, line in imported_names:
            if not hasattr(harness, name):
                failures.append(f'{path.name}:{line}: {NATIVE_HARNESS!r} has no attribute {name!r}')
        for node, scope in scan.attributes:
            if (
                isinstance(node.value, ast.Name)
                and _alias_visible(node.value.id, scope, aliases_by_scope)
                and not hasattr(harness, node.attr)
            ):
                failures.append(
                    f'{path.name}:{node.lineno}: alias {node.value.id!r} references missing '
                    f'{NATIVE_HARNESS}.{node.attr}'
                )
    assert not failures, '\n'.join(failures)


def test_positive_control_is_not_harness_indirection():
    scans, scanner_errors = _scans()
    _assert_scanner_clean(scanner_errors)
    failures = []
    for path, scan in scans:
        if path.name == f'{POSITIVE_CONTROL}.py':
            continue
        for node, _scope in scan.imports:
            for target in _positive_control_targets(node):
                failures.append(
                    f'{path.name}:{node.lineno}: import {target!r} rebuilds the positive-control harness indirection'
                )
    assert not failures, '\n'.join(failures)
