#!/usr/bin/env python3
"""
sira-trust — сбор SHA-256 хешей из пакетов Arch и/или IMA, отправка в SIRA API.

  sira-trust packages /var/cache/pacman/pkg
  sira-trust ima
  sira-trust packages /path/to/pkgs ima
"""

import os
import sys
import gzip
import tarfile
import argparse
from pathlib import Path
from multiprocessing import Pool, cpu_count

import requests

IMA_LOG = "/sys/kernel/security/ima/ascii_runtime_measurements_sha256"
CHUNK = 5000


def hashes_from_pkg(path_str):
    try:
        with tarfile.open(path_str, "r:zst") as tar:
            f = tar.extractfile(tar.getmember(".MTREE"))
            if not f:
                return set()
            mtree = gzip.decompress(f.read()).decode("utf-8", errors="replace")
        out = set()
        for line in mtree.splitlines():
            for tok in line.split():
                if tok.lower().startswith("sha256digest="):
                    h = tok.split("=", 1)[1]
                    if len(h) == 64:
                        out.add(h)
        return out
    except Exception as e:
        print(f"  [!] {Path(path_str).name}: {e}", file=sys.stderr)
        return set()


def collect_packages(directory):
    seen = set()
    pkgs = []
    for pkg in Path(directory).rglob("*.pkg.tar.zst"):
        real = pkg.resolve()
        if real not in seen:
            seen.add(real)
            pkgs.append(str(real))
    return pkgs


def hashes_from_ima():
    if not Path(IMA_LOG).exists():
        print(f"[!] IMA лог не найден: {IMA_LOG}", file=sys.stderr)
        return set()
    out = set()
    with open(IMA_LOG) as f:
        for line in f:
            parts = line.strip().split()
            if len(parts) >= 4:
                h = parts[3].split(":")[-1]
                if len(h) == 64:
                    out.add(h)
    print(f"[*] IMA: {len(out)} хешей")
    return out


def upload(hashes, url, key):
    lst = list(hashes)
    print(f"[*] Отправка {len(lst)} хешей → {url}")
    headers = {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}
    for i in range(0, len(lst), CHUNK):
        chunk = lst[i:i + CHUNK]
        try:
            r = requests.post(url, json={"hashes": chunk}, headers=headers, timeout=30)
            if r.status_code == 200:
                print(f"  [{i + len(chunk)}/{len(lst)}] ok")
            else:
                print(f"  [!] HTTP {r.status_code}: {r.text[:200]}", file=sys.stderr)
        except requests.RequestException as e:
            print(f"  [!] {e}", file=sys.stderr)


def main():
    p = argparse.ArgumentParser(description="Сбор хешей и отправка в SIRA API")
    p.add_argument("sources", nargs="+",
                    help="'ima' и/или 'packages /path/to/dir'")
    p.add_argument("--api-url", default=os.getenv("SIRA_API_UPLOAD_ENDPOINT", ""))
    p.add_argument("--api-key", default=os.getenv("SIRA_API_KEY", ""))
    p.add_argument("-j", "--jobs", type=int, default=cpu_count())
    p.add_argument("--dry-run", action="store_true")
    args = p.parse_args()

    if not args.dry_run and (not args.api_url or not args.api_key):
        p.error("Нужны --api-url и --api-key (или SIRA_API_UPLOAD_ENDPOINT / SIRA_API_KEY)")

    all_hashes = set()
    sources = args.sources
    i = 0
    while i < len(sources):
        if sources[i] == "ima":
            all_hashes.update(hashes_from_ima())
            i += 1
        elif sources[i] == "packages":
            if i + 1 >= len(sources) or sources[i + 1] == "ima":
                p.error("После 'packages' укажите путь к директории")
            pkg_dir = Path(sources[i + 1])
            if not pkg_dir.is_dir():
                p.error(f"Директория не найдена: {pkg_dir}")
            pkgs = collect_packages(pkg_dir)
            print(f"[*] Найдено {len(pkgs)} пакетов в {pkg_dir}")
            with Pool(args.jobs) as pool:
                for result in pool.imap_unordered(hashes_from_pkg, pkgs, chunksize=32):
                    all_hashes.update(result)
            print(f"[*] Пакеты: {len(all_hashes)} хешей")
            i += 2
        else:
            p.error(f"Неизвестный источник: {sources[i]}")

    if not all_hashes:
        print("[!] Хеши не найдены")
        return 1

    print(f"[*] Итого: {len(all_hashes)} уникальных хешей")
    if not args.dry_run:
        upload(all_hashes, args.api_url, args.api_key)
    print("[+] Готово")
    return 0


if __name__ == "__main__":
    sys.exit(main())