#!/usr/bin/env python3
import shutil
import tempfile
import unittest
from pathlib import Path

from evoalign.context_lattice import (
    BoolDimension,
    ContextLattice,
    ContextLatticeError,
    Dimension,
    OrderedEnumDimension,
    SetDimension,
    sha256_file,
)


class TestContextLatticeCoverage(unittest.TestCase):
    def setUp(self):
        self.repo_root = Path(__file__).resolve().parents[2]
        self.lattice_path = self.repo_root / "contracts/context_lattice/context_lattice_v0_1.yaml"
        self.schema_path = self.repo_root / "schemas/ContextLattice.schema.json"
        self.lattice = ContextLattice.load(self.lattice_path, schema_path=self.schema_path)

    def test_covers_any(self):
        self.assertTrue(self.lattice.covers("any", "no_tools"))

    def test_covers_tool_access_any(self):
        self.assertTrue(self.lattice.covers("tool_access:any", "tool_access:web+email"))

    def test_covers_reverse_false(self):
        self.assertFalse(self.lattice.covers("tool_access:web+email", "tool_access:any"))

    def test_covers_web_email_limited(self):
        self.assertTrue(self.lattice.covers("tool_access:web+email", "tool_access:limited"))

    def test_no_tools_not_cover_limited(self):
        self.assertFalse(self.lattice.covers("no_tools", "tool_access:limited"))


class TestContextLatticeValidation(unittest.TestCase):
    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def _write_lattice(self, content: str) -> Path:
        lattice_path = self.test_dir / "context_lattice.yaml"
        lattice_path.write_text(content)
        return lattice_path

    def test_unknown_atom_fails(self):
        lattice_path = self._write_lattice("\n".join([
            "version: \"0.1.0\"",
            "dimensions:",
            "  tool_access:",
            "    type: set",
            "    atoms: [\"web\"]",
            "    top: \"*\"",
            "    bottom: []",
            "contexts:",
            "  any:",
            "    tool_access: [\"drive\"]",
            "metadata:",
            "  created_at: \"2025-01-15T00:00:00Z\"",
            "  rfc_reference: \"RFC-CTX-0001\"",
            "  approvals:",
            "    - role: \"Lead\"",
            "      signature: \"sig\"",
            "      timestamp: \"2025-01-15T00:00:00Z\"",
        ]))
        with self.assertRaises(ContextLatticeError):
            ContextLattice.load(lattice_path)

    def test_missing_dimension_fails(self):
        lattice_path = self._write_lattice("\n".join([
            "version: \"0.1.0\"",
            "dimensions:",
            "  tool_access:",
            "    type: set",
            "    atoms: [\"web\"]",
            "    top: \"*\"",
            "    bottom: []",
            "contexts:",
            "  any:",
            "    autonomy_level: \"assistant\"",
            "metadata:",
            "  created_at: \"2025-01-15T00:00:00Z\"",
            "  rfc_reference: \"RFC-CTX-0001\"",
            "  approvals:",
            "    - role: \"Lead\"",
            "      signature: \"sig\"",
            "      timestamp: \"2025-01-15T00:00:00Z\"",
        ]))
        with self.assertRaises(ContextLatticeError):
            ContextLattice.load(lattice_path)


class TestSetDimension(unittest.TestCase):
    def test_set_dimension_init_errors(self):
        with self.assertRaises(ContextLatticeError):
            SetDimension("tools", [], "*", [])
        with self.assertRaises(ContextLatticeError):
            SetDimension("tools", ["web"], "ALL", [])
        with self.assertRaises(ContextLatticeError):
            SetDimension("tools", ["web"], "*", ["email"])

    def test_set_dimension_normalize_and_leq(self):
        dim = SetDimension("tools", ["web", "email"], "*", [])
        top = dim.normalize("*")
        subset = dim.normalize(["web"])
        superset = dim.normalize(["web", "email"])

        self.assertTrue(dim.leq(top, top))
        self.assertFalse(dim.leq(top, subset))
        self.assertTrue(dim.leq(subset, top))
        self.assertTrue(dim.leq(subset, superset))

        with self.assertRaises(ContextLatticeError):
            dim.normalize("web")
        with self.assertRaises(ContextLatticeError):
            dim.normalize(["drive"])

    def test_set_dimension_join_meet(self):
        dim = SetDimension("tools", ["web", "email"], "*", [])
        top = dim.normalize("*")
        web = dim.normalize(["web"])
        email = dim.normalize(["email"])

        self.assertIs(dim.join([top, web]), top)
        self.assertEqual(dim.join([web, email]), ("email", "web"))

        with self.assertRaises(ContextLatticeError):
            dim.meet([])
        self.assertIs(dim.meet([top]), top)
        self.assertEqual(dim.meet([top, web]), ("web",))


class TestOrderedEnumDimension(unittest.TestCase):
    def test_ordered_enum_init_errors(self):
        with self.assertRaises(ContextLatticeError):
            OrderedEnumDimension("auto", [], "*", "none")
        with self.assertRaises(ContextLatticeError):
            OrderedEnumDimension("auto", ["none", "act"], "invalid", "none")
        with self.assertRaises(ContextLatticeError):
            OrderedEnumDimension("auto", ["none", "act"], "*", "invalid")

    def test_ordered_enum_normalize_and_leq(self):
        dim = OrderedEnumDimension("auto", ["none", "assistant", "act"], "*", "none")
        top = dim.normalize("*")
        none = dim.normalize("none")
        act = dim.normalize("act")

        self.assertTrue(dim.leq(top, top))
        self.assertFalse(dim.leq(top, none))
        self.assertTrue(dim.leq(none, top))
        self.assertTrue(dim.leq(none, act))

        with self.assertRaises(ContextLatticeError):
            dim.normalize("unknown")

    def test_ordered_enum_join_meet(self):
        dim = OrderedEnumDimension("auto", ["none", "assistant", "act"], "*", "none")
        top = dim.normalize("*")
        none = dim.normalize("none")
        act = dim.normalize("act")

        self.assertIs(dim.join([top, none]), top)
        self.assertEqual(dim.join([none, act]), "act")

        with self.assertRaises(ContextLatticeError):
            dim.meet([])
        self.assertIs(dim.meet([top]), top)
        self.assertEqual(dim.meet([top, act]), "act")

    def test_ordered_enum_meet_without_top(self):
        dim = OrderedEnumDimension("auto", ["none", "assistant", "act"], "*", "none")
        none = dim.normalize("none")
        act = dim.normalize("act")
        self.assertEqual(dim.meet([none, act]), "none")


class TestBoolDimension(unittest.TestCase):
    def test_bool_dimension_init_errors(self):
        with self.assertRaises(ContextLatticeError):
            BoolDimension("flag", top="yes", bottom=False)
        with self.assertRaises(ContextLatticeError):
            BoolDimension("flag", top=True, bottom=True)

    def test_bool_dimension_normalize_and_ops(self):
        dim = BoolDimension("flag", top=True, bottom=False)
        self.assertTrue(dim.leq(False, True))
        self.assertFalse(dim.leq(True, False))

        self.assertTrue(dim.join([True, False]))
        self.assertFalse(dim.meet([True, False]))

        with self.assertRaises(ContextLatticeError):
            dim.normalize("true")
        with self.assertRaises(ContextLatticeError):
            dim.join([])
        with self.assertRaises(ContextLatticeError):
            dim.meet([])


class TestContextLatticeLoadFailures(unittest.TestCase):
    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def _write(self, name: str, content: str) -> Path:
        path = self.test_dir / name
        path.write_text(content)
        return path

    def test_load_missing_file_fails(self):
        with self.assertRaises(ContextLatticeError):
            ContextLattice.load(self.test_dir / "missing.yaml")

    def test_schema_missing_fails(self):
        lattice_path = self._write("lattice.yaml", "version: \"0.1.0\"")
        with self.assertRaises(ContextLatticeError):
            ContextLattice.load(lattice_path, schema_path=self.test_dir / "missing.schema.json")

    def test_schema_validation_error(self):
        schema_src = Path(__file__).resolve().parents[2] / "schemas/ContextLattice.schema.json"
        schema_path = self._write("ContextLattice.schema.json", schema_src.read_text())
        lattice_path = self._write("lattice.yaml", "version: \"0.1.0\"")
        with self.assertRaises(ContextLatticeError):
            ContextLattice.load(lattice_path, schema_path=schema_path)


class TestContextLatticeConstruction(unittest.TestCase):
    def test_from_dict_missing_version(self):
        with self.assertRaises(ContextLatticeError):
            ContextLattice.from_dict({"dimensions": {}, "contexts": {}})

    def test_unknown_dimension_type(self):
        with self.assertRaises(ContextLatticeError):
            ContextLattice.from_dict({
                "version": "0.1.0",
                "dimensions": {"x": {"type": "unknown"}},
                "contexts": {"any": {"x": "y"}},
            })

    def test_no_dimensions_fails(self):
        with self.assertRaises(ContextLatticeError):
            ContextLattice.from_dict({
                "version": "0.1.0",
                "dimensions": {},
                "contexts": {"any": {}},
            })

    def test_context_missing_dimension_fails(self):
        with self.assertRaises(ContextLatticeError):
            ContextLattice.from_dict({
                "version": "0.1.0",
                "dimensions": {"tools": {"type": "set", "atoms": ["web"], "top": "*", "bottom": []}},
                "contexts": {"any": {}},
            })

    def test_context_extra_dimension_fails(self):
        with self.assertRaises(ContextLatticeError):
            ContextLattice.from_dict({
                "version": "0.1.0",
                "dimensions": {"tools": {"type": "set", "atoms": ["web"], "top": "*", "bottom": []}},
                "contexts": {"any": {"tools": "*", "extra": "x"}},
            })

    def test_context_not_dict_fails(self):
        with self.assertRaises(ContextLatticeError):
            ContextLattice.from_dict({
                "version": "0.1.0",
                "dimensions": {"tools": {"type": "set", "atoms": ["web"], "top": "*", "bottom": []}},
                "contexts": {"any": "*"},
            })

    def test_no_contexts_fails(self):
        with self.assertRaises(ContextLatticeError):
            ContextLattice.from_dict({
                "version": "0.1.0",
                "dimensions": {"tools": {"type": "set", "atoms": ["web"], "top": "*", "bottom": []}},
                "contexts": {},
            })

    def test_resolve_unknown_context_fails(self):
        lattice = ContextLattice.from_dict({
            "version": "0.1.0",
            "dimensions": {"tools": {"type": "set", "atoms": ["web"], "top": "*", "bottom": []}},
            "contexts": {"any": {"tools": "*"}},
        })
        with self.assertRaises(ContextLatticeError):
            lattice.resolve("missing")

    def test_join_meet_empty_fails(self):
        lattice = ContextLattice.from_dict({
            "version": "0.1.0",
            "dimensions": {"tools": {"type": "set", "atoms": ["web"], "top": "*", "bottom": []}},
            "contexts": {"any": {"tools": "*"}},
        })
        with self.assertRaises(ContextLatticeError):
            lattice.join([])
        with self.assertRaises(ContextLatticeError):
            lattice.meet([])

    def test_join_meet_success(self):
        lattice = ContextLattice.from_dict({
            "version": "0.1.0",
            "dimensions": {"tools": {"type": "set", "atoms": ["web", "email"], "top": "*", "bottom": []}},
            "contexts": {
                "a": {"tools": ["web"]},
                "b": {"tools": ["email"]},
            },
        })
        joined = lattice.join(["a", "b"])
        met = lattice.meet(["a", "b"])
        self.assertEqual(joined.values["tools"], ("email", "web"))
        self.assertEqual(met.values["tools"], ())

    def test_from_dict_multiple_dimension_types(self):
        lattice = ContextLattice.from_dict({
            "version": "0.1.0",
            "dimensions": {
                "tools": {"type": "set", "atoms": ["web"], "top": "*", "bottom": []},
                "auto": {"type": "ordered_enum", "order": ["none", "act"], "top": "*", "bottom": "none"},
                "flag": {"type": "boolean", "top": True, "bottom": False},
            },
            "contexts": {
                "any": {"tools": "*", "auto": "*", "flag": True},
                "none": {"tools": [], "auto": "none", "flag": False},
            },
        })
        self.assertTrue(lattice.covers("any", "none"))


class TestContextLatticeHelpers(unittest.TestCase):
    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def test_sha256_file(self):
        file_path = self.test_dir / "data.txt"
        file_path.write_text("data")
        self.assertEqual(sha256_file(file_path), sha256_file(file_path))


class TestDimensionBase(unittest.TestCase):
    def test_dimension_methods_raise(self):
        dim = Dimension("base", "*", None)
        with self.assertRaises(NotImplementedError):
            dim.normalize("x")
        with self.assertRaises(NotImplementedError):
            dim.leq("a", "b")
        with self.assertRaises(NotImplementedError):
            dim.join(["a"])
        with self.assertRaises(NotImplementedError):
            dim.meet(["a"])

if __name__ == "__main__":
    unittest.main()
