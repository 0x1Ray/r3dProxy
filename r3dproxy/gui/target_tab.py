"""Target tab: a site map tree (host → path) built from history, with scope."""
from __future__ import annotations
from urllib.parse import urlparse

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QSplitter,
                               QPushButton, QLabel, QCheckBox, QLineEdit,
                               QTreeWidget, QTreeWidgetItem, QHeaderView, QMenu,
                               QTabWidget)

from . import theme
from .editor import HttpEditor


class TargetTab(QWidget):
    def __init__(self, ctx, main):
        super().__init__()
        self.ctx = ctx
        self.main = main

        v = QVBoxLayout(self)
        bar = QHBoxLayout()
        refresh = QPushButton("Refresh"); refresh.clicked.connect(self.rebuild)
        discover = QPushButton("Content discovery"); discover.clicked.connect(self.discover_selected)
        bar_discover = discover
        self.scope_only = QCheckBox("in-scope only"); self.scope_only.toggled.connect(self.rebuild)
        self.filter = QLineEdit(); self.filter.setPlaceholderText("filter host/path…")
        self.filter.textChanged.connect(self.rebuild)
        bar.addWidget(refresh); bar.addWidget(discover)
        bar.addWidget(self.scope_only); bar.addWidget(self.filter, 1)
        v.addLayout(bar)

        split = QSplitter(Qt.Horizontal)
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Host / Path", "Method", "Status"])
        self.tree.setColumnWidth(0, 320)
        self.tree.setContextMenuPolicy(Qt.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(self._menu)
        self.tree.itemSelectionChanged.connect(self.show_selected)
        split.addWidget(self.tree)

        viewers = QTabWidget()
        self.req_view = HttpEditor(read_only=True)
        self.resp_view = HttpEditor(read_only=True)
        viewers.addTab(self.req_view, "Request")
        viewers.addTab(self.resp_view, "Response")
        split.addWidget(viewers)
        split.setSizes([520, 560])
        v.addWidget(split)

    def _in_scope(self, host):
        scope = self.ctx.config.get("scope") or []
        host = (host or "").lower()
        return any(s.lower() in host for s in scope if s.strip())

    def rebuild(self):
        self.tree.clear()
        filt = self.filter.text().lower().strip()
        host_nodes = {}
        for rec in self.ctx.store.all():
            host = rec.host or urlparse(rec.url).netloc or "?"
            in_scope = self._in_scope(host)
            if self.scope_only.isChecked() and (self.ctx.config.get("scope") and not in_scope):
                continue
            path = urlparse(rec.url).path or "/"
            if filt and filt not in f"{host}{path}".lower():
                continue
            # host node
            if host not in host_nodes:
                hn = QTreeWidgetItem([host, "", ""])
                hn.setData(0, Qt.UserRole, {"type": "host", "host": host})
                if in_scope:
                    f = hn.font(0); f.setBold(True); hn.setFont(0, f)
                    hn.setForeground(0, QColor(theme.ACCENT))
                self.tree.addTopLevelItem(hn)
                host_nodes[host] = (hn, {})
            hn, children = host_nodes[host]
            # walk path segments
            segs = [s for s in path.split("/") if s] or ["/"]
            parent = hn
            cur_children = children
            acc = ""
            for i, seg in enumerate(segs):
                acc += "/" + seg
                if seg not in cur_children:
                    node = QTreeWidgetItem([seg, "", ""])
                    node.setData(0, Qt.UserRole, {"type": "node", "host": host, "path": acc})
                    parent.addChild(node)
                    cur_children[seg] = (node, {})
                node, nxt = cur_children[seg]
                parent = node
                cur_children = nxt
                if i == len(segs) - 1:
                    node.setText(1, rec.method)
                    node.setText(2, "" if rec.status is None else str(rec.status))
                    node.setData(0, Qt.UserRole, {"type": "leaf", "host": host,
                                                  "path": acc, "fid": rec.fid})
        self.tree.expandToDepth(0)

    def _selected_rec(self):
        items = self.tree.selectedItems()
        if not items:
            return None
        data = items[0].data(0, Qt.UserRole) or {}
        fid = data.get("fid")
        return self.ctx.store.get(fid) if fid else None

    def show_selected(self):
        rec = self._selected_rec()
        if rec:
            self.req_view.set_text(rec.request_text)
            self.resp_view.set_text(rec.response_text)

    def _menu(self, pos):
        items = self.tree.selectedItems()
        if not items:
            it = self.tree.itemAt(pos)
            if it:
                it.setSelected(True); items = [it]
        if not items:
            return
        data = items[0].data(0, Qt.UserRole) or {}
        host = data.get("host")
        menu = QMenu(self)
        if host:
            if self._in_scope(host):
                a_scope = menu.addAction("Remove host from scope")
            else:
                a_scope = menu.addAction("Add host to scope")
        else:
            a_scope = None
        rec = self._selected_rec()
        a_rep = menu.addAction("Send to Repeater") if rec else None
        a_scan = menu.addAction("Send to Scanner") if rec else None
        a_intr = menu.addAction("Send to Intruder") if rec else None
        a_ai = menu.addAction("Send to AI Assistant") if rec else None
        act = menu.exec(self.tree.viewport().mapToGlobal(pos))
        if act is None:
            return
        if act == a_scope and host:
            self._toggle_scope(host)
        elif rec and act == a_rep:
            self.main.send_to_repeater(rec)
        elif rec and act == a_scan:
            self.main.send_to_scanner(rec)
        elif rec and act == a_intr:
            self.main.send_to_intruder(rec)
        elif rec and act == a_ai:
            self.main.send_to_ai(rec.request_text, rec.response_text)

    def _target_for_host(self, host):
        from ..core.sender import Target
        for rec in self.ctx.store.all():
            if rec.host == host:
                port = 443 if rec.scheme == "https" else 80
                netloc = urlparse(rec.url).netloc
                if ":" in netloc:
                    try:
                        port = int(netloc.rsplit(":", 1)[1])
                    except Exception:
                        pass
                return Target(host, port, rec.scheme == "https")
        return Target(host, 443, True)

    def discover_selected(self):
        items = self.tree.selectedItems()
        host = None
        if items:
            host = (items[0].data(0, Qt.UserRole) or {}).get("host")
        if not host:
            from PySide6.QtWidgets import QInputDialog
            host, ok = QInputDialog.getText(self, "Content discovery", "Host:")
            if not ok or not host.strip():
                return
            host = host.strip()
        from .discovery_dialog import ContentDiscoveryDialog
        ContentDiscoveryDialog(self.ctx, self.main, self._target_for_host(host), parent=self).exec()

    def _toggle_scope(self, host):
        scope = list(self.ctx.config.get("scope") or [])
        if self._in_scope(host):
            scope = [s for s in scope if s.lower() not in host.lower() and host.lower() not in s.lower()]
        else:
            if host not in scope:
                scope.append(host)
        self.ctx.config["scope"] = scope
        self.ctx.config.save()
        self.rebuild()
