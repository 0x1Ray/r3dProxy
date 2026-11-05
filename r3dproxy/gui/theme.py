"""Dark 'hawk' theme (red on near-black) applied app-wide via a stylesheet."""

ACCENT = "#e11d2a"
ACCENT_DIM = "#8f1620"
BG = "#0e0f11"
BG2 = "#16181c"
BG3 = "#1e2126"
FG = "#d7dade"
FG_DIM = "#8b9096"
BORDER = "#2a2e35"
OK = "#39d353"
WARN = "#e3b341"

STYLESHEET = f"""
* {{
    font-family: "DejaVu Sans", "Segoe UI", sans-serif;
    font-size: 12px;
    color: {FG};
}}
QMainWindow, QWidget {{ background: {BG}; }}
QTabWidget::pane {{ border: 1px solid {BORDER}; background: {BG}; }}
QTabBar::tab {{
    background: {BG2}; color: {FG_DIM};
    padding: 7px 16px; border: 1px solid {BORDER}; border-bottom: none;
}}
QTabBar::tab:selected {{ background: {BG3}; color: {FG}; border-top: 2px solid {ACCENT}; }}
QTabBar::tab:hover {{ color: {FG}; }}

QPlainTextEdit, QTextEdit, QLineEdit {{
    background: {BG2}; border: 1px solid {BORDER}; border-radius: 4px;
    selection-background-color: {ACCENT_DIM};
    font-family: "DejaVu Sans Mono", "Consolas", monospace;
}}
QPlainTextEdit:focus, QLineEdit:focus {{ border: 1px solid {ACCENT}; }}

QPushButton {{
    background: {BG3}; border: 1px solid {BORDER}; border-radius: 4px;
    padding: 6px 14px; color: {FG};
}}
QPushButton:hover {{ border: 1px solid {ACCENT}; }}
QPushButton:pressed {{ background: {ACCENT_DIM}; }}
QPushButton:disabled {{ color: {FG_DIM}; border-color: {BORDER}; }}
QPushButton#accent {{ background: {ACCENT_DIM}; border: 1px solid {ACCENT}; color: #fff; }}
QPushButton#accent:hover {{ background: {ACCENT}; }}

QHeaderView::section {{
    background: {BG3}; color: {FG_DIM}; padding: 5px; border: none;
    border-right: 1px solid {BORDER}; border-bottom: 1px solid {BORDER};
}}
QTableView, QTableWidget, QTreeWidget, QListWidget {{
    background: {BG2}; gridline-color: {BORDER};
    border: 1px solid {BORDER}; alternate-background-color: {BG};
    selection-background-color: {ACCENT_DIM}; selection-color: #fff;
}}
QTableView::item:selected {{ background: {ACCENT_DIM}; }}

QCheckBox, QLabel {{ background: transparent; }}
QToolBar {{ background: {BG2}; border-bottom: 1px solid {BORDER}; spacing: 6px; padding: 4px; }}
QStatusBar {{ background: {BG2}; color: {FG_DIM}; border-top: 1px solid {BORDER}; }}
QSplitter::handle {{ background: {BORDER}; }}
QComboBox, QSpinBox {{ background: {BG2}; border: 1px solid {BORDER}; border-radius: 4px; padding: 4px; }}
QComboBox QAbstractItemView {{ background: {BG2}; selection-background-color: {ACCENT_DIM}; }}
QScrollBar:vertical {{ background: {BG}; width: 11px; }}
QScrollBar::handle:vertical {{ background: {BG3}; border-radius: 5px; min-height: 24px; }}
QScrollBar::handle:vertical:hover {{ background: {ACCENT_DIM}; }}
QScrollBar::add-line, QScrollBar::sub-line {{ height: 0; }}
QGroupBox {{ border: 1px solid {BORDER}; border-radius: 4px; margin-top: 8px; padding-top: 8px; }}
QGroupBox::title {{ subcontrol-origin: margin; left: 10px; color: {ACCENT}; }}
"""
