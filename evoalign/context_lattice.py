from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping

import yaml
from jsonschema import validate


class ContextLatticeError(ValueError):
    pass


_TOP = object()


class Dimension:
    def __init__(self, name: str, top: Any, bottom: Any) -> None:
        self.name = name
        self.top_symbol = top
        self.bottom = bottom

    def normalize(self, value: Any) -> Any:
        raise NotImplementedError

    def leq(self, a: Any, b: Any) -> bool:
        raise NotImplementedError

    def join(self, values: Iterable[Any]) -> Any:
        raise NotImplementedError

    def meet(self, values: Iterable[Any]) -> Any:
        raise NotImplementedError

    def _is_top(self, value: Any) -> bool:
        return value == self.top_symbol


class SetDimension(Dimension):
    def __init__(self, name: str, atoms: Iterable[str], top: str = "*", bottom: Iterable[str] | None = None) -> None:
        super().__init__(name=name, top=top, bottom=list(bottom or []))
        self.atoms = set(atoms)
        if not self.atoms:
            raise ContextLatticeError(f"Set dimension '{name}' must define atoms")
        if self.top_symbol != "*":
            raise ContextLatticeError(f"Set dimension '{name}' must use '*' for top")
        if not set(self.bottom).issubset(self.atoms):
            raise ContextLatticeError(f"Set dimension '{name}' bottom has unknown atoms")

    def normalize(self, value: Any) -> Any:
        if self._is_top(value):
            return _TOP
        if not isinstance(value, list):
            raise ContextLatticeError(f"Set dimension '{self.name}' expects list or '*'")
        values = list(dict.fromkeys(value))
        unknown = set(values) - self.atoms
        if unknown:
            raise ContextLatticeError(f"Set dimension '{self.name}' has unknown atoms: {sorted(unknown)}")
        return tuple(sorted(values))

    def leq(self, a: Any, b: Any) -> bool:
        if a is _TOP:
            return b is _TOP
        if b is _TOP:
            return True
        return set(a).issubset(set(b))

    def join(self, values: Iterable[Any]) -> Any:
        vals = list(values)
        if any(v is _TOP for v in vals):
            return _TOP
        union = set()
        for v in vals:
            union.update(v)
        return tuple(sorted(union))

    def meet(self, values: Iterable[Any]) -> Any:
        vals = list(values)
        if not vals:
            raise ContextLatticeError(f"Set dimension '{self.name}' meet requires values")
        if any(v is _TOP for v in vals):
            non_top = [v for v in vals if v is not _TOP]
            if not non_top:
                return _TOP
            vals = non_top
        intersect = set(vals[0])
        for v in vals[1:]:
            intersect.intersection_update(v)
        return tuple(sorted(intersect))


class OrderedEnumDimension(Dimension):
    def __init__(self, name: str, order: Iterable[str], top: str, bottom: str) -> None:
        super().__init__(name=name, top=top, bottom=bottom)
        self.order = list(order)
        if not self.order:
            raise ContextLatticeError(f"Ordered enum '{name}' must define order")
        self.rank = {value: idx for idx, value in enumerate(self.order)}
        if top != "*" and top not in self.rank:
            raise ContextLatticeError(f"Ordered enum '{name}' top must be '*' or in order")
        if bottom not in self.rank:
            raise ContextLatticeError(f"Ordered enum '{name}' bottom must be in order")

    def normalize(self, value: Any) -> Any:
        if self._is_top(value):
            return _TOP
        if value not in self.rank:
            raise ContextLatticeError(f"Ordered enum '{self.name}' has unknown value '{value}'")
        return value

    def leq(self, a: Any, b: Any) -> bool:
        if a is _TOP:
            return b is _TOP
        if b is _TOP:
            return True
        return self.rank[a] <= self.rank[b]

    def join(self, values: Iterable[Any]) -> Any:
        vals = list(values)
        if any(v is _TOP for v in vals):
            return _TOP
        return max(vals, key=lambda v: self.rank[v])

    def meet(self, values: Iterable[Any]) -> Any:
        vals = list(values)
        if not vals:
            raise ContextLatticeError(f"Ordered enum '{self.name}' meet requires values")
        if any(v is _TOP for v in vals):
            non_top = [v for v in vals if v is not _TOP]
            if not non_top:
                return _TOP
            vals = non_top
        return min(vals, key=lambda v: self.rank[v])


class BoolDimension(Dimension):
    def __init__(self, name: str, top: bool = True, bottom: bool = False) -> None:
        super().__init__(name=name, top=top, bottom=bottom)
        if not isinstance(top, bool) or not isinstance(bottom, bool):
            raise ContextLatticeError(f"Boolean dimension '{name}' top/bottom must be boolean")
        if top == bottom:
            raise ContextLatticeError(f"Boolean dimension '{name}' top and bottom must differ")

    def normalize(self, value: Any) -> Any:
        if not isinstance(value, bool):
            raise ContextLatticeError(f"Boolean dimension '{self.name}' expects boolean value")
        return value

    def leq(self, a: Any, b: Any) -> bool:
        return (not a) or b

    def join(self, values: Iterable[Any]) -> Any:
        vals = list(values)
        if not vals:
            raise ContextLatticeError(f"Boolean dimension '{self.name}' join requires values")
        return any(vals)

    def meet(self, values: Iterable[Any]) -> Any:
        vals = list(values)
        if not vals:
            raise ContextLatticeError(f"Boolean dimension '{self.name}' meet requires values")
        return all(vals)


@dataclass(frozen=True)
class ContextDescriptor:
    values: Dict[str, Any]


class ContextLattice:
    def __init__(self, version: str, dimensions: Dict[str, Dimension], contexts: Dict[str, ContextDescriptor]) -> None:
        self.version = version
        self.dimensions = dimensions
        self.contexts = contexts

    @classmethod
    def load(cls, lattice_path: Path, schema_path: Path | None = None) -> "ContextLattice":
        if not lattice_path.exists():
            raise ContextLatticeError(f"Lattice file not found: {lattice_path}")
        with lattice_path.open() as f:
            data = yaml.safe_load(f)
        if schema_path:
            try:
                with schema_path.open() as f:
                    schema = json.load(f)
            except OSError as exc:
                raise ContextLatticeError(f"Schema file not found: {schema_path}") from exc
            try:
                validate(instance=data, schema=schema)
            except Exception as exc:
                raise ContextLatticeError(f"Lattice schema validation failed: {exc}") from exc
        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ContextLattice":
        if "version" not in data:
            raise ContextLatticeError("Lattice is missing version")
        dimensions = cls._load_dimensions(data.get("dimensions", {}))
        contexts = cls._load_contexts(data.get("contexts", {}), dimensions)
        return cls(version=data["version"], dimensions=dimensions, contexts=contexts)

    @staticmethod
    def _load_dimensions(dimensions: Mapping[str, Any]) -> Dict[str, Dimension]:
        dims: Dict[str, Dimension] = {}
        for name, spec in dimensions.items():
            dim_type = spec.get("type")
            if dim_type == "set":
                dims[name] = SetDimension(
                    name=name,
                    atoms=spec.get("atoms", []),
                    top=spec.get("top", "*"),
                    bottom=spec.get("bottom", []),
                )
            elif dim_type == "ordered_enum":
                dims[name] = OrderedEnumDimension(
                    name=name,
                    order=spec.get("order", []),
                    top=spec.get("top", "*"),
                    bottom=spec.get("bottom"),
                )
            elif dim_type == "boolean":
                dims[name] = BoolDimension(
                    name=name,
                    top=spec.get("top", True),
                    bottom=spec.get("bottom", False),
                )
            else:
                raise ContextLatticeError(f"Unknown dimension type '{dim_type}' for '{name}'")
        if not dims:
            raise ContextLatticeError("Lattice must define at least one dimension")
        return dims

    @staticmethod
    def _load_contexts(contexts: Mapping[str, Any], dimensions: Mapping[str, Dimension]) -> Dict[str, ContextDescriptor]:
        descriptors: Dict[str, ContextDescriptor] = {}
        dimension_ids = set(dimensions.keys())
        for context_id, raw_desc in contexts.items():
            if not isinstance(raw_desc, dict):
                raise ContextLatticeError(f"Context '{context_id}' must be an object")
            desc_keys = set(raw_desc.keys())
            missing = dimension_ids - desc_keys
            extra = desc_keys - dimension_ids
            if missing:
                raise ContextLatticeError(f"Context '{context_id}' missing dimensions: {sorted(missing)}")
            if extra:
                raise ContextLatticeError(f"Context '{context_id}' has unknown dimensions: {sorted(extra)}")
            normalized: Dict[str, Any] = {}
            for dim_id, dim in dimensions.items():
                normalized[dim_id] = dim.normalize(raw_desc[dim_id])
            descriptors[context_id] = ContextDescriptor(values=normalized)
        if not descriptors:
            raise ContextLatticeError("Lattice must define at least one context")
        return descriptors

    def resolve(self, context_id: str) -> ContextDescriptor:
        try:
            return self.contexts[context_id]
        except KeyError as exc:
            raise ContextLatticeError(f"Unknown context id '{context_id}'") from exc

    def leq(self, left_id: str, right_id: str) -> bool:
        left = self.resolve(left_id)
        right = self.resolve(right_id)
        for dim_id, dim in self.dimensions.items():
            if not dim.leq(left.values[dim_id], right.values[dim_id]):
                return False
        return True

    def covers(self, sup_id: str, sub_id: str) -> bool:
        return self.leq(sub_id, sup_id)

    def join(self, context_ids: Iterable[str]) -> ContextDescriptor:
        ids = list(context_ids)
        if not ids:
            raise ContextLatticeError("join requires at least one context id")
        resolved = [self.resolve(cid) for cid in ids]
        values: Dict[str, Any] = {}
        for dim_id, dim in self.dimensions.items():
            values[dim_id] = dim.join([c.values[dim_id] for c in resolved])
        return ContextDescriptor(values=values)

    def meet(self, context_ids: Iterable[str]) -> ContextDescriptor:
        ids = list(context_ids)
        if not ids:
            raise ContextLatticeError("meet requires at least one context id")
        resolved = [self.resolve(cid) for cid in ids]
        values: Dict[str, Any] = {}
        for dim_id, dim in self.dimensions.items():
            values[dim_id] = dim.meet([c.values[dim_id] for c in resolved])
        return ContextDescriptor(values=values)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            digest.update(chunk)
    return digest.hexdigest()
