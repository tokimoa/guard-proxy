#!/usr/bin/env python3
"""Update popular_packages.json with latest top packages from PyPI, npm, and RubyGems.

Sources:
  - PyPI: hugovk.github.io/top-pypi-packages (top 5000 by monthly downloads)
  - npm: registry.npmjs.org/-/v1/search (by popularity score, paginated)
  - RubyGems: rubygems.org/api/v1/search.json (paginated by downloads)

Usage:
    python scripts/update_popular_packages.py
"""

import json
import sys
import time
from pathlib import Path
from urllib.request import Request, urlopen

POPULAR_PACKAGES_FILE = Path(__file__).resolve().parent.parent / "data" / "popular_packages.json"

PYPI_TOP_URL = "https://hugovk.github.io/top-pypi-packages/top-pypi-packages-30-days.min.json"
NPM_SEARCH_URL = "https://registry.npmjs.org/-/v1/search"
RUBYGEMS_SEARCH_URL = "https://rubygems.org/api/v1/search.json"


def fetch_pypi_top(limit: int = 5000) -> list[str]:
    """Fetch top PyPI packages by download count."""
    print(f"Fetching top {limit} PyPI packages...")
    try:
        with urlopen(PYPI_TOP_URL, timeout=30) as resp:
            data = json.loads(resp.read())
        rows = data.get("rows", [])
        names = [row["project"] for row in rows[:limit]]
        print(f"  Fetched {len(names)} PyPI packages")
        return names
    except Exception as e:
        print(f"  ERROR: Failed to fetch PyPI packages: {e}")
        return []


def fetch_npm_top(current_list: list[str]) -> list[str]:
    """Expand npm popular packages using a curated essential set.

    npm has no bulk "top packages" API. We maintain a curated list of
    well-known packages from the npm ecosystem.
    """
    print(f"Updating npm popular packages (current: {len(current_list)})...")

    essential = {
        "react",
        "vue",
        "angular",
        "svelte",
        "next",
        "nuxt",
        "gatsby",
        "remix",
        "express",
        "fastify",
        "koa",
        "hapi",
        "hono",
        "h3",
        "nitro",
        "webpack",
        "vite",
        "rollup",
        "esbuild",
        "parcel",
        "turbo",
        "swc",
        "babel",
        "typescript",
        "tslib",
        "core-js",
        "regenerator-runtime",
        "jest",
        "mocha",
        "vitest",
        "cypress",
        "playwright",
        "puppeteer",
        "lodash",
        "underscore",
        "ramda",
        "rxjs",
        "immer",
        "zod",
        "yup",
        "axios",
        "node-fetch",
        "got",
        "ky",
        "undici",
        "superagent",
        "ofetch",
        "chalk",
        "ora",
        "commander",
        "yargs",
        "inquirer",
        "prompts",
        "uuid",
        "nanoid",
        "dayjs",
        "moment",
        "date-fns",
        "luxon",
        "debug",
        "winston",
        "pino",
        "bunyan",
        "mongoose",
        "sequelize",
        "prisma",
        "drizzle-orm",
        "typeorm",
        "knex",
        "redis",
        "ioredis",
        "pg",
        "mysql2",
        "better-sqlite3",
        "mongodb",
        "jsonwebtoken",
        "bcrypt",
        "argon2",
        "passport",
        "helmet",
        "cors",
        "eslint",
        "prettier",
        "stylelint",
        "lint-staged",
        "husky",
        "nodemon",
        "concurrently",
        "cross-env",
        "dotenv",
        "config",
        "tailwindcss",
        "postcss",
        "autoprefixer",
        "sass",
        "less",
        "bootstrap",
        "styled-components",
        "react-dom",
        "react-router",
        "react-router-dom",
        "redux",
        "mobx",
        "zustand",
        "jotai",
        "recoil",
        "semver",
        "minimatch",
        "glob",
        "fast-glob",
        "chokidar",
        "fs-extra",
        "mkdirp",
        "rimraf",
        "globby",
        "qs",
        "cheerio",
        "jsdom",
        "xml2js",
        "sharp",
        "socket.io",
        "ws",
        "nodemailer",
        "handlebars",
        "ejs",
        "pug",
        "pm2",
        "npm",
        "yarn",
        "pnpm",
        "lerna",
        "nx",
    }

    all_names = set(current_list) | essential
    names = sorted(all_names)
    print(f"  npm: {len(names)} packages (was {len(current_list)})")
    return names


def fetch_rubygems_top(limit: int = 1000) -> list[str]:
    """Fetch popular RubyGems by searching with common terms.

    RubyGems search API requires a query term. We search for common
    single-letter terms and deduplicate to build a popularity list.
    """
    print(f"Fetching top {limit} RubyGems...")

    # Essential RubyGems that must always be in the list
    essential_gems = {
        "rails",
        "rake",
        "bundler",
        "rspec",
        "nokogiri",
        "puma",
        "sidekiq",
        "devise",
        "pg",
        "redis",
        "sinatra",
        "grape",
        "rack",
        "faraday",
        "httparty",
        "jwt",
        "omniauth",
        "pundit",
        "paper_trail",
        "rubocop",
        "simplecov",
        "factory_bot",
        "faker",
        "capybara",
        "minitest",
        "activerecord",
        "activesupport",
        "actionpack",
        "railties",
        "webpacker",
        "turbo-rails",
        "stimulus-rails",
        "importmap-rails",
        "bootsnap",
        "spring",
        "listen",
        "thor",
        "concurrent-ruby",
        "i18n",
        "tzinfo",
        "zeitwerk",
        "sprockets",
        "sassc",
        "terser",
        "oj",
        "multi_json",
        "json",
        "msgpack",
        "protobuf",
        "grpc",
        "rest-client",
        "typhoeus",
        "http",
        "net-http",
        "openssl",
        "aws-sdk",
        "google-cloud",
        "fog",
        "carrierwave",
        "shrine",
        "image_processing",
        "mini_magick",
        "prawn",
        "wicked_pdf",
        "liquid",
        "slim",
        "haml",
        "erb",
        "tilt",
        "pagy",
        "kaminari",
        "will_paginate",
        "ransack",
        "searchkick",
        "roda",
        "hanami",
        "dry-rb",
        "sequel",
        "mongoid",
    }
    names_set: set[str] = set(essential_gems)

    # Search with popular terms to discover many gems
    search_terms = [
        "rails",
        "ruby",
        "api",
        "web",
        "test",
        "json",
        "http",
        "db",
        "cli",
        "aws",
        "auth",
        "log",
        "net",
        "xml",
        "csv",
        "sql",
        "io",
        "a",
        "b",
        "c",
        "d",
        "e",
        "r",
        "s",
        "t",
    ]

    for term in search_terms:
        if len(names_set) >= limit:
            break
        for page in range(1, 4):  # 3 pages per term
            url = f"{RUBYGEMS_SEARCH_URL}?query={term}&page={page}"
            try:
                req = Request(url, headers={"Accept": "application/json"})
                with urlopen(req, timeout=10) as resp:
                    data = json.loads(resp.read())
                if not isinstance(data, list) or not data:
                    break
                for gem in data:
                    if isinstance(gem, dict) and gem.get("name"):
                        names_set.add(gem["name"])
                time.sleep(0.3)  # Rate limit
            except Exception:
                break

    names = sorted(names_set)[:limit]
    print(f"  Fetched {len(names)} RubyGems")
    return names


def safety_check(current_count: int, new_count: int, ecosystem: str) -> bool:
    """Prevent data loss from API failures."""
    if current_count > 100 and new_count < current_count * 0.5:
        print(f"  SAFETY: {ecosystem} dropped from {current_count} to {new_count} — keeping current")
        return False
    return True


def main() -> int:
    # Load current file
    if POPULAR_PACKAGES_FILE.exists():
        current = json.loads(POPULAR_PACKAGES_FILE.read_text())
    else:
        current = {"npm": [], "pypi": [], "rubygems": []}

    # Fetch all ecosystems
    pypi_new = fetch_pypi_top(5000)
    npm_new = fetch_npm_top(current.get("npm", []))
    rubygems_new = fetch_rubygems_top(1000)

    # Safety checks and update
    if pypi_new and safety_check(len(current.get("pypi", [])), len(pypi_new), "pypi"):
        current["pypi"] = pypi_new

    if npm_new and safety_check(len(current.get("npm", [])), len(npm_new), "npm"):
        current["npm"] = npm_new

    if rubygems_new and safety_check(len(current.get("rubygems", [])), len(rubygems_new), "rubygems"):
        current["rubygems"] = rubygems_new

    # Write back
    POPULAR_PACKAGES_FILE.write_text(json.dumps(current, indent=2, ensure_ascii=False) + "\n")
    print(f"\nUpdated {POPULAR_PACKAGES_FILE}")
    for eco in ("npm", "pypi", "rubygems"):
        print(f"  {eco}: {len(current.get(eco, []))} packages")

    return 0


if __name__ == "__main__":
    sys.exit(main())
