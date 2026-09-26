# FILE: tests/test_router_startup_symbols.py
# VERSION: 1.0.0
# START_MODULE_CONTRACT
#   PURPOSE: Guard the process entry point against NameError at startup — every global a top-level callable touches must exist.
#   SCOPE: static resolution of loaded global names inside module-level functions of src/router.py.
#   DEPENDS: stdlib ast
#   LINKS: M-ROUTER, V-M-ROUTER
#   ROLE: TEST
#   MAP_MODE: LOCALS
# END_MODULE_CONTRACT
#
# START_CHANGE_SUMMARY
#   LAST_CHANGE: v1.0.1 - параметры функций учитываются как доступные имена: без этого проверка
#                считала неразрешённым каждый аргумент и краснела на всех функциях с параметрами.
#   PREVIOUS: v1.0.0 - регресс 20.09.2026: Phase-17 удалила `_make_alert_sender`, оставив вызов в `main`;
#                сьют из 750 тестов этого не заметил, служба падала с NameError на старте.
#                Проверка ловит любой такой случай статически, без запуска сервиса.
# END_CHANGE_SUMMARY
"""Проверка: у функций точки входа не бывает имён, которых нет в модуле.

Причина теста — реальный отказ 20.09.2026: правка удалила функцию `_make_alert_sender`,
но оставила её вызов в `main`. Полный сьют был зелёным, а служба не поднималась вовсе
(`NameError` на старте). Тест разбирает модуль как дерево разбора и сверяет имена,
которые читаются внутри каждой функции верхнего уровня, с тем, что реально определено
в модуле, во вложенных функциях и во встроенных именах.
"""

import ast
import builtins
import pathlib
import unittest

ROUTER_PATH = pathlib.Path(__file__).resolve().parents[1] / "src" / "router.py"


def _module_level_names(tree: ast.Module) -> set[str]:
    """Собрать имена, определённые на уровне модуля (включая ветки `if`/`try`)."""
    names: set[str] = set()

    def harvest(statements: list[ast.stmt]) -> None:
        for node in statements:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                names.add(node.name)
            elif isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        names.add(target.id)
            elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                names.add(node.target.id)
            elif isinstance(node, (ast.Import, ast.ImportFrom)):
                for alias in node.names:
                    names.add(alias.asname or alias.name.split(".")[0])
            elif isinstance(node, (ast.If, ast.Try, ast.With)):
                harvest(node.body)
                harvest(getattr(node, "orelse", []) or [])
                harvest(getattr(node, "finalbody", []) or [])
                for handler in getattr(node, "handlers", []) or []:
                    harvest(handler.body)

    harvest(tree.body)
    return names


def _function_scope_names(node: ast.AST) -> set[str]:
    """Имена, доступные внутри функции: параметры, локальные привязки, вложенные def/class."""
    names: set[str] = set()
    for inner in ast.walk(node):
        if isinstance(inner, ast.Name) and isinstance(inner.ctx, (ast.Store, ast.Del)):
            names.add(inner.id)
        elif isinstance(inner, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(inner.name)
        elif isinstance(inner, (ast.Import, ast.ImportFrom)):
            for alias in inner.names:
                names.add(alias.asname or alias.name.split(".")[0])
        elif isinstance(inner, ast.ExceptHandler) and inner.name:
            names.add(inner.name)
        elif isinstance(inner, ast.arguments):
            # Параметры функции — такие же доступные имена, как локальные привязки. Без этой
            # ветки проверка считала неразрешённым каждый аргумент («node», «service», «config»)
            # и краснела на всех функциях с параметрами (правка 20.09.2026).
            names.update(arg.arg for arg in (*inner.posonlyargs, *inner.args, *inner.kwonlyargs))
            if inner.vararg is not None:
                names.add(inner.vararg.arg)
            if inner.kwarg is not None:
                names.add(inner.kwarg.arg)
        elif isinstance(inner, (ast.comprehension,)):
            for target in ast.walk(inner.target):
                if isinstance(target, ast.Name):
                    names.add(target.id)
    return names


class RouterStartupSymbolsTest(unittest.TestCase):
    """Точка входа не должна ссылаться на несуществующие имена."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.source = ROUTER_PATH.read_text(encoding="utf-8")
        cls.tree = ast.parse(cls.source)
        cls.module_names = _module_level_names(cls.tree)

    def _undefined_in(self, function: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
        used = {
            node.id
            for node in ast.walk(function)
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load)
        }
        available = self.module_names | _function_scope_names(function)
        return {
            name
            for name in used
            if name not in available and not hasattr(builtins, name)
        }

    def test_main_resolves_every_global_it_uses(self) -> None:
        """`main` — то, что запускает systemd; здесь недопустимо ни одно неразрешённое имя."""
        entry = [n for n in self.tree.body if isinstance(n, ast.FunctionDef) and n.name == "main"]
        self.assertEqual(1, len(entry), "в модуле должна быть ровно одна функция main")
        missing = self._undefined_in(entry[0])
        self.assertEqual(
            set(),
            missing,
            f"в main используются неопределённые имена: {sorted(missing)} — служба упадёт на старте",
        )

    def test_every_module_function_resolves_its_globals(self) -> None:
        """Тот же разбор для всех функций верхнего уровня: дефект не должен прятаться рядом с main."""
        broken: dict[str, list[str]] = {}
        for node in self.tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                missing = self._undefined_in(node)
                if missing:
                    broken[node.name] = sorted(missing)
        self.assertEqual({}, broken, f"неразрешённые имена в функциях модуля: {broken}")

    def test_the_alert_sender_builder_is_defined_and_wired(self) -> None:
        """Именно эта функция была потеряна при правке — держим отдельную проверку её наличия."""
        self.assertIn("_make_alert_sender", self.module_names)
        self.assertIn("alert_sender=_make_alert_sender(config)", self.source)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
