#!/usr/bin/env python3
"""Sharded template cache — cache compiled {{var}} templates for playbooks.

Mirrors Osmedeus internal/template/sharded_engine.go (16 shards, LRU 64) but
as a simple Python helper for BountyHarness playbook rendering.

Usage:
    template_cache.py render --template "Hello {{name}}" --vars '{"name": "world"}'
    template_cache.py clear
"""

import argparse
import hashlib
import json
import re
from pathlib import Path
from collections import OrderedDict

CACHE_SIZE = 64
SHARDS = 16


class ShardedCache:
    def __init__(self, max_size: int = CACHE_SIZE, shards: int = SHARDS):
        self.shards = [OrderedDict() for _ in range(shards)]
        self.max_size = max_size
        self.shards_count = shards

    def _shard(self, key: str) -> int:
        return int(hashlib.sha256(key.encode()).hexdigest(), 16) % self.shards_count

    def get(self, key: str):
        shard = self.shards[self._shard(key)]
        if key in shard:
            shard.move_to_end(key)
            return shard[key]
        return None

    def set(self, key: str, value):
        shard = self.shards[self._shard(key)]
        shard[key] = value
        shard.move_to_end(key)
        # Evict oldest if over per-shard quota
        per_shard = max(1, self.max_size // self.shards_count)
        while len(shard) > per_shard:
            shard.popitem(last=False)

    def clear(self):
        for s in self.shards:
            s.clear()


# Global cache instance
_cache = ShardedCache()

VAR_RE = re.compile(r"\{\{([a-zA-Z_][a-zA-Z0-9_]*)\}\}")


def render_template(template: str, vars_dict: dict) -> str:
    cached = _cache.get(template)
    if cached is not None:
        # Cached is compiled regex replacement function
        return cached(vars_dict)

    # Compile: create function that does substitution
    def _render(variables: dict) -> str:
        def repl(m):
            key = m.group(1)
            return str(variables.get(key, m.group(0)))
        return VAR_RE.sub(repl, template)

    _cache.set(template, _render)
    return _render(vars_dict)


def main():
    parser = argparse.ArgumentParser(description="Sharded template cache")
    sub = parser.add_subparsers(dest="command")

    p_render = sub.add_parser("render", help="Render a template")
    p_render.add_argument("--template", required=True)
    p_render.add_argument("--vars", required=True, help="JSON dict of variables")
    p_render.add_argument("--output", help="Output file")

    p_clear = sub.add_parser("clear", help="Clear cache")

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(2)

    if args.command == "render":
        vars_dict = json.loads(args.vars)
        result = render_template(args.template, vars_dict)
        if args.output:
            Path(args.output).parent.mkdir(parents=True, exist_ok=True)
            Path(args.output).write_text(result, encoding="utf-8")
        print(result)
    elif args.command == "clear":
        _cache.clear()
        print("Cache cleared")


if __name__ == "__main__":
    main()
