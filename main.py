import os
import logging
import shutil
from datetime import datetime
from pathlib import Path
from sqlalchemy import create_engine, text
from rich.console import Console
from rich.prompt import Prompt, Confirm
from rich.panel import Panel
from rich.table import Table
from rich.columns import Columns
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich import box
from rich.text import Text
from rich.align import Align
from rich.style import Style
from services import VaultService
from repositories import AES256GCMChunkedProvider, LocalStorageRepository, SQLiteRepository, KeyRepository, KeyNotFoundError
from models import DocumentModel

logging.basicConfig(level=logging.WARNING)
logger = logging.getLogger(__name__)

DB_PATH = os.path.join(os.path.dirname(__file__), "vault.db")
STORAGE_PATH = "./secure_storage"
_ENGINE = create_engine(f"sqlite:///{DB_PATH}", echo=False)
console = Console()

SUSPICIOUS = ('.exe', '.sh', '.bat', '.cmd', '.dll', '.vbs', '.ps1')

# ── vault ───────────────────────────────────────────────────────────────
def get_vault():
    kr = KeyRepository(db_url=f"sqlite:///{DB_PATH}", engine=_ENGINE)
    try:
        mk = kr.get_active_key().master_key_hex
    except KeyNotFoundError:
        mk = os.urandom(32).hex()
        kr.create_key_version(mk)
    return VaultService(
        crypto=AES256GCMChunkedProvider(key_hex=mk),
        storage=LocalStorageRepository(base_path=STORAGE_PATH),
        sql_db=SQLiteRepository(db_url=f"sqlite:///{DB_PATH}", engine=_ENGINE),
        key_repo=kr
    ), SQLiteRepository(db_url=f"sqlite:///{DB_PATH}", engine=_ENGINE)

def sz(b):
    if not b: return "—"
    if b < 1024: return f"{b} B"
    if b < 1024**2: return f"{b/1024:.1f} KB"
    return f"{b/1024**2:.1f} MB"

def ago(dt):
    if not dt: return "—"
    d = datetime.now() - dt
    if d.days > 365: return f"{d.days//365}y"
    if d.days > 30: return f"{d.days//30}mo"
    if d.days > 0: return f"{d.days}d"
    if d.seconds > 3600: return f"{d.seconds//3600}h"
    if d.seconds > 60: return f"{d.seconds//60}m"
    return "now"

# ── menu card ───────────────────────────────────────────────────────────
def menu_panel() -> Panel:
    items = [
        ("[bold cyan] 1", "  🔒  Encrypt",        "files or folders"),
        ("[bold green] 2", "  🔓  Decrypt",        "by document ID"),
        ("[bold yellow] 3", "  📋  List",           "browse vault"),
        ("[bold magenta] 4", "  🔄  Rotate Key",    "new master key"),
        ("[bold blue] 5", "  📊  Stats",           "vault health"),
        ("[bold red] 0", "  🚪  Exit",            "close vault"),
    ]
    lines = []
    for key, emoji, desc in items:
        lines.append(f"{key}{emoji}  [dim]{desc}[/]")
    return Panel(
        Align.center("\n".join(lines)),
        title="[bold bright_white]  ⚡ COMMAND CENTER  [/]",
        border_style="bright_blue",
        box=box.DOUBLE_EDGE,
        padding=(1, 4),
        subtitle="[dim]select an option[/]",
    )

# ── status card ─────────────────────────────────────────────────────────
def status_panel(vault, sql_db) -> Panel:
    with sql_db.Session() as s:
        docs = s.query(DocumentModel).all()
        n = len(docs)
        total = sum(d.size_bytes for d in docs if d.size_bytes)
    enc = sum(1 for _ in Path(STORAGE_PATH).glob("*.enc")) if os.path.isdir(STORAGE_PATH) else 0
    ki = vault._key_repo.get_active_key()

    return Panel(
        Align.center(
            f"[bold bright_white]{n}[/]  documents\n"
            f"[bold bright_white]{sz(total)}[/]  stored\n"
            f"[bold bright_white]#{ki.id}[/]  key\n"
            f"[bold bright_white]{ago(ki.created_at)}[/]  key age"
        ),
        title="[bold bright_green]  📦 VAULT STATUS  [/]",
        border_style="bright_green",
        box=box.DOUBLE_EDGE,
        padding=(1, 4),
    )

# ── encrypt ─────────────────────────────────────────────────────────────
def encrypt_flow(vault):
    path = Prompt.ask("[bold cyan]➜[/] Path").strip()
    if not os.path.exists(path):
        console.print("[red]✗ not found[/]"); return

    files = [os.path.join(r, f) for r, _, fs in os.walk(path) for f in fs] if os.path.isdir(path) else [path]
    safe = [f for f in files if not f.lower().endswith(SUSPICIOUS)]
    nope = len(files) - len(safe)

    if nope: console.print(f"[yellow]⚠ {nope} suspicious skipped[/]")
    if not safe: console.print("[red]✗ nothing to encrypt[/]"); return
    if len(safe) > 1: console.print(f"[blue]📁 {len(safe)} files[/]")

    ok, fail = 0, 0
    with Progress(SpinnerColumn(), TextColumn("{task.description}"), BarColumn(), console=console) as p:
        t = p.add_task("", total=len(safe))
        for f in safe:
            p.update(t, description=f"🔐  {os.path.basename(f)[:45]}")
            try:
                with open(f, "rb") as fh:
                    vault.upload_secure_document(os.path.basename(f), fh, actor="CLI")
                ok += 1
            except: fail += 1
            p.advance(t)

    c = "green" if not fail else "yellow"
    console.print(Panel(f"[bold {c}]✅ {ok} ok" + (f"  ✗ {fail} fail" if fail else "") + "[/]", border_style=c))

# ── decrypt ─────────────────────────────────────────────────────────────
def decrypt_flow(vault):
    doc_id = Prompt.ask("[bold green]➜[/] Document ID").strip()
    if not doc_id: return

    row = _ENGINE.connect().execute(text("SELECT original_filename,size_bytes,created_at FROM documents WHERE id=:id"), {"id": doc_id}).fetchone()
    if row:
        console.print(f"[dim]{row[0]}  •  {sz(row[1])}  •  {ago(row[2])}[/]")

    dest = os.path.expanduser(Prompt.ask("[bold green]➜[/] Output dir", default="~/Vault_Recuperados"))
    if os.path.exists(dest) and not os.path.isdir(dest): console.print("[red]✗ not a dir[/]"); return
    os.makedirs(dest, exist_ok=True)

    with Progress(SpinnerColumn(), TextColumn("{task.description}"), console=console) as p:
        p.add_task(description="🔓  Decrypting...")
        try:
            fn, stream = vault.download_secure_document(doc_id, actor="CLI")
            path = os.path.join(dest, f"recup_{fn}")
            with open(path, "wb") as f:
                shutil.copyfileobj(stream, f)
            stream.close()
            console.print(Panel(f"[green]✅ {path}[/]", border_style="green"))
        except Exception as e:
            console.print(Panel(f"[red]✗ {e}[/]", border_style="red"))

# ── list ────────────────────────────────────────────────────────────────
def list_flow(sql_db):
    with sql_db.Session() as s:
        docs = s.query(DocumentModel).order_by(DocumentModel.created_at.desc()).all()
    if not docs: console.print("[yellow]📂 empty[/]"); return

    t = Table(title=f"", box=box.MINIMAL_HEAVY_HEAD, border_style="bright_blue", header_style="bold")
    t.add_column("ID", style="cyan", width=10)
    t.add_column("Filename")
    t.add_column("Size", justify="right", width=8)
    t.add_column("Age", justify="right", width=6)
    t.add_column("Key", width=5)
    for d in docs:
        t.add_row(d.id[:8], d.original_filename or "?", sz(d.size_bytes), ago(d.created_at), f"#{d.key_id}" if d.key_id else "—")
    console.print(Panel(t, title=f"[bold]  📄 DOCUMENTS ({len(docs)})  [/]", border_style="bright_blue", box=box.DOUBLE_EDGE))

# ── rotate ──────────────────────────────────────────────────────────────
def rotate_flow(vault):
    if not Confirm.ask("[yellow]⚠ Rotate key?"): return
    with Progress(SpinnerColumn(), TextColumn("{task.description}"), console=console) as p:
        p.add_task(description="🔄  Rotating...")
        r = vault.rotate_key_manually()
    console.print(Panel(f"[green]✅ Key #{r['key_id']}[/]", border_style="green"))

# ── main loop ───────────────────────────────────────────────────────────
def main():
    vault, sql_db = get_vault()
    console.clear()

    BANNER = """
╔══════════════════════════════════════════════════════════╗
║                🔐  S E C U R E   V A U L T              ║
║           AES-256-GCM  ─  Key Rotation  ─  Audit        ║
╚══════════════════════════════════════════════════════════╝"""

    while True:
        console.print()
        console.print(Align.center(BANNER, style="bold bright_white"))
        console.print()
        cols = Columns([menu_panel(), status_panel(vault, sql_db)], equal=True, align="center")
        console.print(cols)
        console.print()

        choice = Prompt.ask("[bold]  Select", choices=list("012345"), ).strip()
        console.print()

        if choice == "1": encrypt_flow(vault)
        elif choice == "2": decrypt_flow(vault)
        elif choice == "3": list_flow(sql_db)
        elif choice == "4": rotate_flow(vault)
        elif choice == "5": console.print(status_panel(vault, sql_db))
        elif choice == "0":
            console.print(Panel("[bold red]🔐 Vault locked[/]", border_style="red"))
            break

        console.print()

if __name__ == "__main__":
    main()
