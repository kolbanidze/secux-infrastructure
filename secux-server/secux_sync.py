#!/usr/bin/env python3
# /home/secux/secux_sync.py
import os
import subprocess
import tarfile
import base64
import tempfile
from pathlib import Path
from multiprocessing import Pool, cpu_count

DEST = Path("/srv/arch-mirror")
SOURCE_RSYNC = "rsync://repository.su/archlinux"
GPG_KEY = "6299E92E77AC4B098BB2F172A48097D18B638500"
CORES = cpu_count()
REPOS = ["core", "extra", "multilib"]


def sync_repo():
    print("\n[*] Запуск rsync...")
    subprocess.run([
        "rsync", "-rlptvH", "--delete-after", "--delay-updates",
        "--safe-links",
        "--exclude=*.sig",
        "--exclude=iso/", "--exclude=images/", "--exclude=other/",
        "--exclude=archive/", "--exclude=*debug*/",
        "--exclude=pool/*-debug",
        "--exclude=wsl/", "--exclude=sources/", '--exclude=/secux-repo/',
        SOURCE_RSYNC, str(DEST)
    ], check=True)


def _extract_field(text, field):
    lines = text.split('\n')
    try:
        index = lines.index(field) + 1
    except ValueError:
        return None
    if index >= len(lines):
        return None
    value_parts = []
    for i in range(index, len(lines)):
        line = lines[i].strip()
        if not line or (line.startswith('%') and line.endswith('%')):
            break
        value_parts.append(line)
    return ''.join(value_parts) if value_parts else None


def _find_pkg(filename, repo_dir, pool_dir):
    """Найти реальный путь к пакету (repo_dir или pool)."""
    p = repo_dir / filename
    if p.exists():
        return p
    p = pool_dir / filename
    if p.exists():
        return p
    return None


def verify_and_sign_worker(args):
    """Проверяет upstream подпись, создаёт .sig в repo_dir."""
    filename, pgp_signature, repo_dir_str, pool_dir_str = args
    repo_dir = Path(repo_dir_str)
    pool_dir = Path(pool_dir_str)

    pkg_path = _find_pkg(filename, repo_dir, pool_dir)
    if pkg_path is None:
        return filename, False, "файл не найден"

    sig_output = repo_dir / (filename + ".sig")

    # Декодирование PGPSIG
    try:
        sig_bytes = base64.b64decode(pgp_signature)
    except Exception:
        return filename, False, "ошибка декодирования PGPSIG"

    # Проверка upstream подписи
    with tempfile.NamedTemporaryFile(suffix=".sig", delete=True) as tmp:
        tmp.write(sig_bytes)
        tmp.flush()
        proc = subprocess.run(
            ["pacman-key", "--verify", tmp.name, str(pkg_path)],
            capture_output=True, text=True,
        )
        if proc.returncode != 0:
            return filename, False, \
                f"upstream подпись невалидна: {proc.stderr.strip()}"

    # Создание нашей подписи сразу в repo_dir
    proc = subprocess.run(
        ["gpg", "--batch", "--yes", "--detach-sign", "--no-armor",
         "--local-user", GPG_KEY,
         "--output", str(sig_output),
         str(pkg_path)],
        capture_output=True, text=True,
    )
    if proc.returncode != 0:
        return filename, False, f"gpg sign: {proc.stderr.strip()}"

    return filename, True, None


def cleanup_orphan_sigs(directory, label):
    """Удалить .sig без соответствующего пакета."""
    orphans = 0
    for sig in directory.glob("*.pkg.tar.*.sig"):
        pkg = sig.with_suffix('')  # убираем .sig
        if not pkg.exists():
            sig.unlink()
            orphans += 1
    if orphans:
        print(f"  [{label}] удалено {orphans} осиротевших .sig")


def sign_db(repo_dir: Path, repo: str):
    """Подписать upstream БД нашим ключом + обновить симлинки."""
    for name in [f"{repo}.db.tar.gz", f"{repo}.files.tar.gz"]:
        db_path = repo_dir / name
        if not db_path.exists():
            continue

        sig_path = repo_dir / (name + ".sig")

        proc = subprocess.run([
            "gpg", "--batch", "--yes", "--detach-sign", "--no-armor",
            "--local-user", GPG_KEY,
            "--output", str(sig_path),
            str(db_path),
        ], capture_output=True, text=True)

        if proc.returncode != 0:
            print(f"[!] Ошибка подписи {name}: {proc.stderr.strip()}")
            continue

        # Симлинки: repo.db -> repo.db.tar.gz и repo.db.sig -> repo.db.tar.gz.sig
        short = name.replace(".tar.gz", "")
        for src, dst in [(name, short), (name + ".sig", short + ".sig")]:
            link = repo_dir / dst
            if link.exists() or link.is_symlink():
                link.unlink()
            link.symlink_to(src)


def process_repo(repo):
    pool_dir = DEST / "pool" / "packages"
    repo_dir = DEST / repo / "os" / "x86_64"
    db_path = repo_dir / f"{repo}.db.tar.gz"

    if not db_path.exists():
        print(f"[!] БД не найдена: {db_path}")
        return

    entries = {}  # filename -> pgpsig
    with tarfile.open(str(db_path), "r:gz") as tf:
        for member in tf.getmembers():
            if not member.name.endswith("/desc"):
                continue
            data = tf.extractfile(member)
            if data is None:
                continue
            text = data.read().decode()
            fn = _extract_field(text, "%FILENAME%")
            sig = _extract_field(text, "%PGPSIG%")
            if fn and sig:
                entries[fn] = sig

    print(f"[*] {repo}: {len(entries)} пакетов в upstream БД")

    cleanup_orphan_sigs(repo_dir, repo)

    to_sign = []
    for filename, pgpsig in entries.items():
        sig_path = repo_dir / (filename + ".sig")
        if not sig_path.exists():
            to_sign.append((filename, pgpsig, str(repo_dir), str(pool_dir)))

    print(f"[*] {repo}: нужно подписать {len(to_sign)} из {len(entries)}")

    if to_sign:
        signed = failed = 0
        with Pool(CORES) as p:
            results = p.map(verify_and_sign_worker, to_sign)
        for pkg_name, ok, err in results:
            if ok:
                signed += 1
            else:
                print(f"  [!] {pkg_name}: {err}")
                failed += 1
        print(f"[*] {repo}: подписано {signed}, ошибок {failed}")
    else:
        print(f"[*] {repo}: все пакеты уже подписаны")

    sign_db(repo_dir, repo)
    print(f"[+] {repo}: готово\n")


if __name__ == "__main__":
    try:
        os.environ["GPG_TTY"] = os.readlink("/proc/self/fd/0")
    except OSError:
        pass

    sync_repo()

    pool_dir = DEST / "pool" / "packages"
    if pool_dir.exists():
        cleanup_orphan_sigs(pool_dir, "pool")

    for r in REPOS:
        process_repo(r)

    print("\n[+] ВСЁ ГОТОВО")