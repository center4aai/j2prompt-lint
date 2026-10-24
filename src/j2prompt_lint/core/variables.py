from __future__ import annotations
from collections.abc import Iterable
from dataclasses import dataclass
from itertools import chain
from jinja2 import TemplateAssertionError, nodes
from jinja2.idtracking import VAR_LOAD_RESOLVE, Symbols
from jinja2.visitor import NodeVisitor

class _NamesFound(Exception):
    pass

class _EndSequence(Exception):
    pass

class _SpecialNames(NodeVisitor):

    def __init__(self, names: Iterable[str]) -> None:
        self.remaining = set(names)
        self.found: set[str] = set()

    def visit_Name(self, node: nodes.Name) -> None:
        if node.ctx == 'load' and node.name in self.remaining:
            self.found.add(node.name)
            if self.found == self.remaining:
                raise _NamesFound
        else:
            self.remaining.discard(node.name)

    def visit_Block(self, node: nodes.Block) -> None:
        pass

def _special_names(body: Iterable[nodes.Node], names: Iterable[str]) -> set[str]:
    visitor = _SpecialNames(names)
    try:
        for node in body:
            visitor.visit(node)
    except _NamesFound:
        pass
    return visitor.found

@dataclass(slots=True)
class _Frame:
    symbols: Symbols
    toplevel: bool = False
    rootlevel: bool = False

    def inner(self) -> _Frame:
        return _Frame(Symbols(parent=self.symbols))

    def soft(self) -> _Frame:
        return _Frame(self.symbols, toplevel=self.toplevel)
_DEFAULT_NODES = frozenset({nodes.Template, nodes.Output, nodes.If, nodes.For, nodes.Macro, nodes.CallBlock, nodes.FilterBlock, nodes.With, nodes.Assign, nodes.AssignBlock, nodes.Import, nodes.FromImport, nodes.Include, nodes.Extends, nodes.Block, nodes.Scope, nodes.ScopedEvalContextModifier, nodes.EvalContextModifier, nodes.ExprStmt, nodes.Name, nodes.NSRef, nodes.Const, nodes.TemplateData, nodes.Tuple, nodes.List, nodes.Dict, nodes.Pair, nodes.Keyword, nodes.Getitem, nodes.Getattr, nodes.Slice, nodes.Call, nodes.Filter, nodes.Test, nodes.CondExpr, nodes.Concat, nodes.Compare, nodes.Operand, nodes.And, nodes.Or, nodes.Not, nodes.Add, nodes.Sub, nodes.Mul, nodes.Div, nodes.FloorDiv, nodes.Pow, nodes.Mod, nodes.Neg, nodes.Pos})

class _Candidates(NodeVisitor):

    def __init__(self, globals_: Iterable[str]) -> None:
        self.globals = frozenset(globals_)
        self.names: set[str] = set()
        self.extends_count = 0
        self.known_extends = False

    def _enter(self, frame: _Frame) -> None:
        for action, name in frame.symbols.loads.values():
            if action == VAR_LOAD_RESOLVE and name not in self.globals:
                self.names.add(name)

    def _sequence(self, body: Iterable[nodes.Node], frame: _Frame) -> None:
        try:
            for child in body:
                self.visit(child, frame)
        except _EndSequence:
            pass

    def template(self, node: nodes.Template) -> None:
        blocks: dict[str, nodes.Block] = {}
        for block in node.find_all(nodes.Block):
            if block.name in blocks:
                raise TemplateAssertionError(f'block {block.name!r} defined twice', block.lineno)
            blocks[block.name] = block
        root = _Frame(Symbols(), toplevel=True, rootlevel=True)
        if 'self' in _special_names(node.body, ('self',)):
            root.symbols.declare_parameter('self')
        root.symbols.analyze_node(node)
        self._enter(root)
        self._sequence(node.body, root)
        for block in blocks.values():
            frame = _Frame(Symbols())
            for name in _special_names(block.body, ('self', 'super')):
                frame.symbols.declare_parameter(name)
            frame.symbols.analyze_node(block)
            self._enter(frame)
            self._sequence(block.body, frame)

    def generic_visit(self, node: nodes.Node, frame: _Frame, **kwargs: object) -> None:
        for child in node.iter_child_nodes():
            self.visit(child, frame)

    def visit_Name(self, node: nodes.Name, frame: _Frame) -> None:
        frame.symbols.ref(node.name)

    def visit_NSRef(self, node: nodes.NSRef, frame: _Frame) -> None:
        frame.symbols.ref(node.name)

    def visit_Block(self, node: nodes.Block, frame: _Frame) -> None:
        pass

    def visit_If(self, node: nodes.If, frame: _Frame) -> None:
        soft = frame.soft()
        self.visit(node.test, soft)
        self._sequence(node.body, soft)
        for branch in node.elif_:
            self.visit(branch.test, soft)
            self._sequence(branch.body, soft)
        self._sequence(node.else_, soft)

    def _macro(self, node: nodes.Macro | nodes.CallBlock, outer: _Frame) -> None:
        frame = outer.inner()
        frame.symbols.analyze_node(node)
        special = _special_names(node.body, ('caller', 'kwargs', 'varargs'))
        parameters = [arg.name for arg in node.args]
        if 'caller' in special:
            if 'caller' in parameters:
                position = parameters.index('caller') - len(parameters)
                if position < -len(node.defaults):
                    raise TemplateAssertionError('The special "caller" parameter needs a default.', node.lineno)
            else:
                frame.symbols.declare_parameter('caller')
        for name in ('kwargs', 'varargs'):
            if name in special and name not in parameters:
                frame.symbols.declare_parameter(name)
        frame.symbols.analyze_node(node)
        self._enter(frame)
        for default in node.defaults:
            self.visit(default, frame)
        self._sequence(node.body, frame)

    def visit_Macro(self, node: nodes.Macro, frame: _Frame) -> None:
        self._macro(node, frame)
        frame.symbols.ref(node.name)

    def visit_CallBlock(self, node: nodes.CallBlock, frame: _Frame) -> None:
        self._macro(node, frame)
        self.visit(node.call, frame)

    def visit_For(self, node: nodes.For, frame: _Frame) -> None:
        body = frame.inner()
        extended = node.recursive or 'loop' in _special_names(node.body, ('loop',)) or any((block.scoped for block in node.find_all(nodes.Block)))
        if extended:
            body.symbols.declare_parameter('loop')
        body.symbols.analyze_node(node, for_branch='body')
        otherwise = frame.inner()
        if node.else_:
            otherwise.symbols.analyze_node(node, for_branch='else')
        if node.test is not None:
            predicate = frame.inner()
            predicate.symbols.analyze_node(node, for_branch='test')
            self._enter(predicate)
            self.visit(node.target, body)
            self.visit(node.test, predicate)
        for name in node.find_all(nodes.Name):
            if name.ctx == 'store' and name.name == 'loop':
                raise TemplateAssertionError("Can't assign to special loop variable in for-loop target", name.lineno)
        self.visit(node.target, body)
        self.visit(node.iter, frame)
        self._enter(body)
        self._sequence(node.body, body)
        if node.else_:
            self._enter(otherwise)
            self._sequence(node.else_, otherwise)

    def visit_With(self, node: nodes.With, frame: _Frame) -> None:
        inner = frame.inner()
        inner.symbols.analyze_node(node)
        self._enter(inner)
        for target, value in zip(node.targets, node.values, strict=True):
            self.visit(target, inner)
            self.visit(value, frame)
        self._sequence(node.body, inner)

    def visit_FilterBlock(self, node: nodes.FilterBlock, frame: _Frame) -> None:
        inner = frame.inner()
        inner.symbols.analyze_node(node)
        self._enter(inner)
        self._sequence(node.body, inner)
        self.visit(node.filter, inner)

    def visit_AssignBlock(self, node: nodes.AssignBlock, frame: _Frame) -> None:
        inner = frame.inner()
        inner.symbols.analyze_node(node)
        self._enter(inner)
        self._sequence(node.body, inner)
        self.visit(node.target, frame)
        if node.filter is not None:
            self.visit(node.filter, inner)

    def visit_Scope(self, node: nodes.Scope, frame: _Frame) -> None:
        inner = frame.inner()
        inner.symbols.analyze_node(node)
        self._enter(inner)
        self._sequence(node.body, inner)

    def visit_Extends(self, node: nodes.Extends, frame: _Frame) -> None:
        if not frame.toplevel:
            raise TemplateAssertionError('cannot use extend from a non top-level scope', node.lineno)
        if self.extends_count and self.known_extends:
            raise _EndSequence
        self.visit(node.template, frame)
        self.extends_count += 1
        if frame.rootlevel:
            self.known_extends = True

def undeclared_candidates(ast: nodes.Template) -> frozenset[str]:
    for node in chain((ast,), ast.find_all(nodes.Node)):
        if type(node) not in _DEFAULT_NODES:
            raise TemplateAssertionError(f'Unsupported non-default-parser node: {type(node).__name__}', node.lineno)
    environment = ast.environment
    if environment is None:
        raise TemplateAssertionError('Missing parser environment', ast.lineno or 1)
    reader = _Candidates(environment.globals.keys())
    reader.template(ast)
    return frozenset(reader.names)
