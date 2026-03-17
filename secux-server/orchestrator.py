#!/usr/bin/env python3
# /home/server/orchestrator.py
import time
import subprocess
import logging
import shutil
import re
from pathlib import Path

INCOMING_DIR = Path("/home/server/incoming")
NGINX_DIR = Path("/srv/arch-mirror/secux-repo/")
HF_DIR = Path("/home/server/hf-repo")
HF_REPO_DIR = HF_DIR / "repo"
DB_NAME = "secux-repo.db.tar.gz"
CHECK_INTERVAL = 5  # секунд

# Arch Linux package parsing
PKG_PATTERN = re.compile(r"^(.+)-([^-]+)-([^-]+)-(x86_64|any)\.pkg\.tar\.(zst|xz)$")

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

def process_packages():
    packages = list(INCOMING_DIR.glob("*.pkg.tar.zst"))
    sigs = list(INCOMING_DIR.glob("*.sig"))

    if not packages and not sigs:
        return

    logging.info(f"Found new packages: {len(packages)}, signatures: {len(sigs)}.")

    # Parse names and remove old pkgs
    for file in packages:
        match = PKG_PATTERN.match(file.name)
        if match:
            pkgname = match.group(1)
            
            for existing in HF_REPO_DIR.glob(f"{pkgname}-*.pkg.tar.zst"):
                ex_match = PKG_PATTERN.match(existing.name)
                
                if ex_match and ex_match.group(1) == pkgname and existing.name != file.name:
                    logging.info(f"Removing legacy: {existing.name}")
                    existing.unlink()
                    
                    old_sig = existing.with_name(existing.name + ".sig")
                    if old_sig.exists():
                        old_sig.unlink()

    pkg_names =[]
    for file in packages + sigs:
        dest = HF_REPO_DIR / file.name
        shutil.move(str(file), str(dest))
        logging.info(f"Adding: {file.name}")
        if str(file).endswith(".pkg.tar.zst"):
            pkg_names.append(file.name)

    if not pkg_names:
        return

    logging.info("Updaing pacman...")
    cmd_repo_add =["repo-add", "-R", "--verify", '--sign', '--key', '6299E92E77AC4B098BB2F172A48097D18B638500', "-n", DB_NAME] + pkg_names
    subprocess.run(cmd_repo_add, cwd=HF_REPO_DIR, check=True, capture_output=True)

    for old_file in HF_REPO_DIR.glob("*.old*"):
        logging.info(f"Removing old backups: {old_file.name}")
        old_file.unlink(missing_ok=True)
    
    logging.info("Pushing to HuggingFace (Git LFS)...")
    status = subprocess.run(["git", "status", "--porcelain"], cwd=HF_DIR, capture_output=True, text=True)
    
    if status.stdout.strip():
        subprocess.run(["git", "checkout", "--orphan", "temp"], cwd=HF_DIR, check=True, capture_output=True)
        subprocess.run(["git", "add", "."], cwd=HF_DIR, check=True)
        commit_msg = f"Auto-update: processed {len(packages)} packages"
        subprocess.run(["git", "commit", "-m", commit_msg], cwd=HF_DIR, check=True, capture_output=True)
        subprocess.run(["git", "branch", "-D", "main"], cwd=HF_DIR, check=True, capture_output=True)
        subprocess.run(["git", "branch", "-m", "main"], cwd=HF_DIR, check=True, capture_output=True)
        subprocess.run(["git", "reflog", "expire", "--expire=now", "--all"], cwd=HF_DIR, check=True, capture_output=True)
        subprocess.run(["git", "gc", "--prune=now"], cwd=HF_DIR, check=True, capture_output=True)

        subprocess.run(["git", "push", '-f', "origin", "main"], cwd=HF_DIR, check=True)
        logging.info("Successfully pushed to HuggingFace!")
    else:
        logging.info("No changes.")

    logging.info("Syncing git repo with secux mirror...")
    cmd_rsync =[
        "rsync", "-avz", "--delete", "--exclude=.git*",
        f"{HF_REPO_DIR}/", f"{NGINX_DIR}/"
    ]
    subprocess.run(cmd_rsync, check=True)

    logging.info("Done")

    

def main():
    INCOMING_DIR.mkdir(parents=True, exist_ok=True)
    NGINX_DIR.mkdir(parents=True, exist_ok=True)

    logging.info(">>> Secux Orchestrator")
    
    while True:
        try:
            process_packages()
        except subprocess.CalledProcessError as e:
            logging.error(f"Error executing: {e.cmd}")
            if e.stderr:
                logging.error(e.stderr.decode('utf-8'))
        except Exception as e:
            logging.error(f"Unexpected error: {e}")
        
        time.sleep(CHECK_INTERVAL)

if __name__ == "__main__":
    main()