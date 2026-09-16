#!/usr/bin/env python3
import argparse
import os
import shutil
import sys

parser = argparse.ArgumentParser()
parser.add_argument("path", nargs="?", default="/var/cache/layersentry-oneswap")
parser.add_argument("--min-free-gib", type=int, default=10)
args = parser.parse_args()

root = os.stat("/").st_dev
scratch = os.stat(args.path).st_dev
if root == scratch:
    print(f"{args.path} must be a dedicated mounted filesystem, not the appliance OS disk", file=sys.stderr)
    raise SystemExit(2)
free = shutil.disk_usage(args.path).free
minimum = args.min_free_gib * 1024 ** 3
if free < minimum:
    print(f"{args.path} has only {free} bytes free; require at least {minimum}", file=sys.stderr)
    raise SystemExit(3)
print(f"scratch_ok path={args.path} free_bytes={free}")
