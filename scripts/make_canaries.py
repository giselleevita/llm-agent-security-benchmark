from __future__ import annotations

import argparse


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--count", type=int, default=2)
    args = ap.parse_args()

    for i in range(1, args.count + 1):
        print(f"CANARY_KEY_{i:03d}")


if __name__ == "__main__":
    main()
