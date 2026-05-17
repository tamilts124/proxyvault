#!/usr/bin/env python3
"""
plugin_loader.py — hot-reloadable intercept-hook plugin system.

Drop any *.py file into the hooks_dir (default: hooks/) and the proxy will
load it automatically.  Edit or replace the file while the proxy is running
and it reloads within ~1 second — no restart required.

Plugin contract
───────────────
A plugin is any .py file that exposes one or both of:

    def on_request(ctx: PluginContext) -> bool | None:
        ...

    def on_response(ctx: PluginContext) -> None:
        ...

Return False from on_request to short-circuit: the request is still
forwarded to the server, but subsequent plugins and the DB-recording step
in ProxyAddon are both skipped.  Any other return value (including None)
continues the chain.

PluginContext fields
────────────────────
  url          str       full URL
  domain       str       netloc only, e.g. "api.example.com"
  method       str       "GET", "POST", …
  req_headers  dict      {lowercase-name: value-or-list}
  req_body     str|None  decoded request body (None if binary)
  status_code  int|None  HTTP status (None in on_request)
  res_headers  dict      response headers (empty in on_request)
  res_body     str|None  HTML body when saved, else None (on_response only)
  flow         object    raw mitmproxy HTTPFlow (advanced use — may change)
  meta         dict      mutable scratch space shared between on_request and
                         on_response for the *same flow*; use it to pass data
                         from request-side to response-side in a single plugin.

Example plugin (hooks/log_post.py)
───────────────────────────────────
    import logging
    log = logging.getLogger("plugin.log_post")

    def on_request(ctx):
        if ctx.method == "POST":
            log.info(f"POST  {ctx.url}  body={ctx.req_body[:120]}")

Watchdog dependency
───────────────────
    pip install watchdog

If watchdog is not installed the system still works — plugins are loaded at
startup but won't hot-reload.  A warning is printed to the log.
"""

import importlib
import importlib.util
import logging
import sys
import threading
import traceback
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

log = logging.getLogger("plugin_loader")

# ──────────────────────────────────────────────────────────
# Public context object passed to every plugin hook
# ──────────────────────────────────────────────────────────

@dataclass
class PluginContext:
    url:         str
    domain:      str
    method:      str
    req_headers: dict
    req_body:    str | None
    status_code: int | None        = None
    res_headers: dict              = field(default_factory=dict)
    res_body:    str | None        = None
    flow:        Any               = None   # raw mitmproxy HTTPFlow
    meta:        dict              = field(default_factory=dict)


# ──────────────────────────────────────────────────────────
# Minimal RW-lock  (stdlib only — no extra deps)
# ──────────────────────────────────────────────────────────

class _RWLock:
    """Allow many concurrent readers OR one exclusive writer."""

    def __init__(self):
        self._read_ready = threading.Condition(threading.Lock())
        self._readers    = 0

    def acquire_read(self):
        with self._read_ready:
            self._readers += 1

    def release_read(self):
        with self._read_ready:
            self._readers -= 1
            if self._readers == 0:
                self._read_ready.notify_all()

    def acquire_write(self):
        self._read_ready.acquire()
        while self._readers > 0:
            self._read_ready.wait()

    def release_write(self):
        self._read_ready.release()


# ──────────────────────────────────────────────────────────
# Loaded plugin representation
# ──────────────────────────────────────────────────────────

@dataclass
class _Plugin:
    name:       str           # stem of the file, e.g. "log_post"
    path:       Path
    on_request:  Any = None   # callable or None
    on_response: Any = None   # callable or None


# ──────────────────────────────────────────────────────────
# PluginLoader
# ──────────────────────────────────────────────────────────

class PluginLoader:
    """
    Loads all *.py files in *hooks_dir*, calls their on_request /
    on_response hooks in filename-alphabetical order, and hot-reloads them
    whenever a file is created, modified, or deleted.
    """

    def __init__(self, hooks_dir: str | Path):
        self._dir      = Path(hooks_dir)
        self._plugins: list[_Plugin] = []
        self._lock     = _RWLock()
        self._observer = None   # watchdog observer (set in start())

        self._dir.mkdir(parents=True, exist_ok=True)

        # Flow-level meta store: id(flow) → dict, so on_request can pass data
        # to on_response within the same plugin across hooks.
        self._flow_meta: dict[int, dict] = {}
        self._flow_meta_lock = threading.Lock()

        self._load_all()

    # ── loading ───────────────────────────────────────────────────────────

    def _load_file(self, path: Path) -> _Plugin | None:
        """Import (or reimport) a single plugin file. Returns None on error."""
        name     = path.stem
        mod_name = f"_proxy_plugin_{name}"
        try:
            spec   = importlib.util.spec_from_file_location(mod_name, path)
            module = importlib.util.module_from_spec(spec)
            # Isolate from sys.modules so reloads always get a fresh module
            spec.loader.exec_module(module)

            plugin = _Plugin(
                name        = name,
                path        = path,
                on_request  = getattr(module, "on_request",  None),
                on_response = getattr(module, "on_response", None),
            )
            if not plugin.on_request and not plugin.on_response:
                log.warning(f"[PLUGIN] {name}: no on_request or on_response — skipping")
                return None

            hooks = [h for h, fn in [("on_request", plugin.on_request),
                                      ("on_response", plugin.on_response)] if fn]
            log.info(f"[PLUGIN] loaded  {name}  ({', '.join(hooks)})")
            return plugin

        except Exception:
            log.error(f"[PLUGIN] failed to load {path.name}:\n"
                      + traceback.format_exc(limit=6))
            return None

    def _load_all(self):
        """Load every *.py file in hooks_dir, sorted by name."""
        files   = sorted(self._dir.glob("*.py"))
        plugins = [p for f in files if (p := self._load_file(f)) is not None]
        self._lock.acquire_write()
        try:
            self._plugins = plugins
        finally:
            self._lock.release_write()
        log.info(f"[PLUGIN] {len(plugins)}/{len(files)} plugin(s) active in {self._dir}")

    def _reload_file(self, path: Path):
        """Reload a single file and swap it in the list atomically."""
        name   = path.stem
        plugin = self._load_file(path) if path.exists() else None

        self._lock.acquire_write()
        try:
            # Remove the old version of this plugin (if present)
            self._plugins = [p for p in self._plugins if p.name != name]
            if plugin is not None:
                # Re-insert in sorted position
                self._plugins.append(plugin)
                self._plugins.sort(key=lambda p: p.name)
                log.info(f"[PLUGIN] reloaded  {name}")
            else:
                log.info(f"[PLUGIN] unloaded  {name}")
        finally:
            self._lock.release_write()

    # ── hot-reload watcher ────────────────────────────────────────────────

    def start(self):
        """Start the watchdog file-system observer (if watchdog is installed)."""
        try:
            from watchdog.observers import Observer
            from watchdog.events    import FileSystemEventHandler

            loader = self   # capture for the inner class

            class _Handler(FileSystemEventHandler):
                def _is_py(self, event):
                    return not event.is_directory and event.src_path.endswith(".py")

                def on_modified(self, event):
                    if self._is_py(event):
                        loader._reload_file(Path(event.src_path))

                def on_created(self, event):
                    if self._is_py(event):
                        loader._reload_file(Path(event.src_path))

                def on_deleted(self, event):
                    if self._is_py(event):
                        loader._reload_file(Path(event.src_path))

                # watchdog fires on_moved when an editor does atomic saves
                # (write temp → rename).  Treat rename-into-dir as a create.
                def on_moved(self, event):
                    if not event.is_directory and event.dest_path.endswith(".py"):
                        loader._reload_file(Path(event.dest_path))

            self._observer = Observer()
            self._observer.schedule(_Handler(), str(self._dir), recursive=False)
            self._observer.daemon = True
            self._observer.start()
            log.info(f"[PLUGIN] watching {self._dir}  (hot-reload active)")

        except ImportError:
            log.warning(
                "[PLUGIN] watchdog not installed — plugins will NOT hot-reload.\n"
                "         Run:  pip install watchdog"
            )

    def stop(self):
        """Stop the watchdog observer cleanly."""
        if self._observer and self._observer.is_alive():
            self._observer.stop()
            self._observer.join(timeout=2)

    # ── per-flow meta management ──────────────────────────────────────────

    def _get_meta(self, flow) -> dict:
        fid = id(flow)
        with self._flow_meta_lock:
            if fid not in self._flow_meta:
                self._flow_meta[fid] = {}
            return self._flow_meta[fid]

    def _drop_meta(self, flow):
        with self._flow_meta_lock:
            self._flow_meta.pop(id(flow), None)

    # ── public call surface (called from ProxyAddon) ──────────────────────

    def run_request_hooks(self, ctx: PluginContext) -> bool:
        """
        Call on_request on every plugin in order.

        Returns True if processing should continue (DB record, response hooks),
        False if any plugin returned False (short-circuit).
        """
        ctx.meta = self._get_meta(ctx.flow)

        self._lock.acquire_read()
        try:
            plugins = list(self._plugins)   # snapshot
        finally:
            self._lock.release_read()

        for plugin in plugins:
            if plugin.on_request is None:
                continue
            try:
                result = plugin.on_request(ctx)
                if result is False:
                    log.debug(f"[PLUGIN] {plugin.name}.on_request short-circuited {ctx.url[:60]}")
                    self._drop_meta(ctx.flow)
                    return False
            except Exception:
                log.error(f"[PLUGIN] {plugin.name}.on_request raised:\n"
                          + traceback.format_exc(limit=6))
        return True

    def run_response_hooks(self, ctx: PluginContext) -> None:
        """Call on_response on every plugin in order."""
        ctx.meta = self._get_meta(ctx.flow)

        self._lock.acquire_read()
        try:
            plugins = list(self._plugins)
        finally:
            self._lock.release_read()

        try:
            for plugin in plugins:
                if plugin.on_response is None:
                    continue
                try:
                    plugin.on_response(ctx)
                except Exception:
                    log.error(f"[PLUGIN] {plugin.name}.on_response raised:\n"
                              + traceback.format_exc(limit=6))
        finally:
            self._drop_meta(ctx.flow)

    # ── introspection (for dashboard / viewer) ────────────────────────────

    def list_plugins(self) -> list[dict]:
        """Return a JSON-serialisable summary of loaded plugins."""
        self._lock.acquire_read()
        try:
            return [
                {
                    "name":         p.name,
                    "path":         str(p.path),
                    "has_request":  p.on_request  is not None,
                    "has_response": p.on_response is not None,
                }
                for p in self._plugins
            ]
        finally:
            self._lock.release_read()


# ──────────────────────────────────────────────────────────
# Module-level singleton (set by proxy.py main())
# ──────────────────────────────────────────────────────────

_loader: PluginLoader | None = None


def init(hooks_dir: str | Path) -> PluginLoader:
    """Create the global PluginLoader, start the watcher, return it."""
    global _loader
    _loader = PluginLoader(hooks_dir)
    _loader.start()
    return _loader


def get() -> PluginLoader | None:
    """Return the active loader, or None if not initialised."""
    return _loader
