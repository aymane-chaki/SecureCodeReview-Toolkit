#!/usr/bin/env python3

import argparse
import sys
import pathlib
import shutil
import subprocess
import requests
import xml.etree.ElementTree as ET
from urllib.parse import quote
from concurrent.futures import ThreadPoolExecutor, as_completed


# --- ANSI Color Codes ---
if sys.stdout.isatty():
    COLOR_RESET, COLOR_RED, COLOR_GREEN, COLOR_YELLOW, COLOR_BLUE, \
    COLOR_MAGENTA, COLOR_CYAN, COLOR_WHITE, COLOR_BOLD, COLOR_DIM = \
    ("\033[0m", "\033[91m", "\033[92m", "\033[93m", "\033[94m",
     "\033[95m", "\033[96m", "\033[97m", "\033[1m", "\033[2m")
else:
    COLOR_RESET, COLOR_RED, COLOR_GREEN, COLOR_YELLOW, COLOR_BLUE, \
    COLOR_MAGENTA, COLOR_CYAN, COLOR_WHITE, COLOR_BOLD, COLOR_DIM = \
    ("", "", "", "", "", "", "", "", "", "")


# --- Constants & Templates ---
MAVEN_NS = {"mvn": "http://maven.apache.org/POM/4.0.0"}
DEPS_DEV_API = "https://deps.dev/_/s/{system}/p/{package}/v/{version}"

# google mavem repos (useful for android projects)
GOOGLE_MAVEN_REPO = "https://dl.google.com/dl/android/maven2"
# snapshot repo
SONATYPE_SNAPSHOTS_REPO = "https://s01.oss.sonatype.org/content/repositories/snapshots"

POM_TEMPLATE = """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>
    <groupId>security.assessment</groupId>
    <artifactId>prep-odcared-project</artifactId>
    <version>1.0.0-SNAPSHOT</version>
    <dependencies>
{dependencies}
    </dependencies>
    <repositories>
{repositories}
    </repositories>
    <properties>
{properties}
    </properties>
</project>
"""

DEP_TEMPLATE = """        <dependency>
            <groupId>{g}</groupId>
            <artifactId>{a}</artifactId>
            <version>{v}</version>{type_block}{scope_block}
        </dependency>"""


# --- Small helpers ---
def color(text, color_code="", bold=False, dim=False):
    if not sys.stdout.isatty():
        return str(text)

    prefix = ""
    if bold:
        prefix += COLOR_BOLD
    if dim:
        prefix += COLOR_DIM

    return f"{prefix}{color_code}{text}{COLOR_RESET}"


def log_info(msg):
    print(color("[*]", COLOR_CYAN, bold=True), msg)


def log_warn(msg):
    print(color("[!]", COLOR_YELLOW, bold=True), msg)


def log_ok(msg):
    print(color("[+]", COLOR_GREEN, bold=True), msg)


def log_err(msg):
    print(color("[ERROR]", COLOR_RED, bold=True), msg, file=sys.stderr)


def ensure_directory(path):
    path.mkdir(parents=True, exist_ok=True)


def clean_directory(path):
    if path.exists():
        try:
            shutil.rmtree(path)
        except OSError as e:
            log_err(f"Error removing {path}: {e}")
    path.mkdir(parents=True, exist_ok=True)


def text_of(node):
    if node is None or node.text is None:
        return None
    return node.text.strip()


def normalize_repo_urls(values):
    """
    Accept repeated --repo-url and also comma-separated lists.
    Returns a set of urls.
    """
    out = set()
    if not values:
        return out

    for v in values:
        if not v:
            continue
        parts = [p.strip() for p in str(v).split(",") if p.strip()]
        for p in parts:
            out.add(p)

    return out


# --- 1. POM Parsing & Verification Logic ---
def parse_pom(filepath, ignored_gids):
    """
    Returns:
      deps: set of tuples (g, a, v, dep_type, scope)
      props: dict
      repos: set of repository URLs
      coords: tuple (groupId, artifactId) resolved with parent fallback
    """
    deps = set()
    props = {}
    repos = set()
    coords = (None, None)

    try:
        tree = ET.parse(filepath)
        root = tree.getroot()

        gid = text_of(root.find("mvn:groupId", MAVEN_NS))
        aid = text_of(root.find("mvn:artifactId", MAVEN_NS))

        if not gid:
            gid = text_of(root.find("mvn:parent/mvn:groupId", MAVEN_NS))

        if gid and aid:
            coords = (gid, aid)

        for repo_url in root.findall(".//mvn:repositories/mvn:repository/mvn:url", MAVEN_NS):
            url = text_of(repo_url)
            if url:
                repos.add(url)

        for prop_group in root.findall(".//mvn:properties", MAVEN_NS):
            for child in prop_group:
                tag = child.tag.replace(f"{{{MAVEN_NS['mvn']}}}", "")
                val = text_of(child)
                if val:
                    props[tag] = val

        for node in root.findall(".//mvn:dependency", MAVEN_NS):
            g = text_of(node.find("mvn:groupId", MAVEN_NS))
            a = text_of(node.find("mvn:artifactId", MAVEN_NS))
            v = text_of(node.find("mvn:version", MAVEN_NS))
            t = text_of(node.find("mvn:type", MAVEN_NS))
            s = text_of(node.find("mvn:scope", MAVEN_NS))

            if not g or not a or not v:
                continue

            if g in ignored_gids:
                continue

            if g.startswith("${project."):
                continue

            dep_type = (t or "jar").strip()
            scope = (s or "").strip()

            deps.add((g, a, v, dep_type, scope))

    except ET.ParseError:
        pass

    return deps, props, repos, coords


def check_single_dep(dep_tuple, session, system):
    g, a, v, dep_type, scope = dep_tuple

    if not v:
        return None

    if v.startswith("${"):
        return dep_tuple

    url = DEPS_DEV_API.format(system=system, package=quote(f"{g}:{a}", safe=""), version=v)
    try:
        if session.get(url, timeout=5).status_code == 200:
            return dep_tuple
    except Exception:
        pass

    return None


def verify_dependencies(dep_list, workers=20):
    valid_deps = []
    total = len(dep_list)
    completed = 0

    with requests.Session() as session:
        with ThreadPoolExecutor(max_workers=workers) as executor:
            future_to_dep = {
                executor.submit(check_single_dep, dep, session, "maven"): dep
                for dep in dep_list
            }

            for future in as_completed(future_to_dep):
                completed += 1
                print(f"\rProgress: [{completed}/{total}] verified", end="", flush=True)
                result = future.result()
                if result:
                    valid_deps.append(result)

    print(f"\r{' ' * 60}\r", end="")
    return sorted(valid_deps)


def build_repositories_block(repo_urls):
    blocks = []
    i = 1
    for url in sorted(repo_urls):
        blocks.append(
            "        <repository>\n"
            f"            <id>repo{i}</id>\n"
            f"            <url>{url}</url>\n"
            "        </repository>"
        )
        i += 1
    return "\n".join(blocks)


def generate_pom(filename, deps, props, repo_urls):
    dep_lines = []
    for g, a, v, dep_type, scope in deps:
        type_block = ""
        scope_block = ""

        if dep_type and dep_type != "jar":
            type_block = f"\n            <type>{dep_type}</type>"
        if scope:
            scope_block = f"\n            <scope>{scope}</scope>"

        dep_lines.append(DEP_TEMPLATE.format(
            g=g, a=a, v=v,
            type_block=type_block,
            scope_block=scope_block
        ))

    dep_str = "\n".join(dep_lines)
    prop_str = "\n".join([f"        <{k}>{val}</{k}>" for k, val in props.items()])
    repos_str = build_repositories_block(repo_urls)

    with open(filename, "w", encoding="utf-8") as f:
        f.write(POM_TEMPLATE.format(dependencies=dep_str, properties=prop_str, repositories=repos_str))


# --- 2. File Gathering Logic ---
def gather_js_files(source_path, dest_path, clean=False):
    log_info("Gather JS files into a single folder...")

    if clean:
        clean_directory(dest_path)
    else:
        ensure_directory(dest_path)

    count = 0
    for js_file in source_path.rglob("*.js"):
        if "node_modules" in str(js_file):
            continue

        try:
            shutil.copy2(js_file, dest_path)
            count += 1
        except Exception as e:
            log_err(f"Error copying {js_file.name}: {e}")

    return count


def gather_jars(pom_path, dest_path, clean=False):
    log_info("Gather JAR files of the maven project dependencies into a single folder...")

    if clean:
        clean_directory(dest_path)
    else:
        ensure_directory(dest_path)

    cmd = [
        "mvn", "-q",
        "dependency:copy-dependencies",
        f"-DoutputDirectory={dest_path.absolute()}",
        "-f", str(pom_path),
    ]

    try:
        subprocess.run(cmd, check=True)
        return len(list(dest_path.glob("*.jar")))
    except subprocess.CalledProcessError:
        log_err("Maven command failed. Ensure 'mvn' is installed and pom.xml is valid.")
        return 0
    except FileNotFoundError:
        log_err("Maven executable 'mvn' not found in PATH.")
        return 0


# --- Main function ---
def main():
    parser = argparse.ArgumentParser(
        description=f"{COLOR_BOLD}ODC Preparator: Gather JS and Java dependencies.{COLOR_RESET}",
        formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=30, width=120),
        epilog=f"""
{COLOR_BOLD}Usage:{COLOR_RESET}
  python prep-odc.py -f ./my-project
  python prep-odc.py -f ./my-project -o ./odc-staging
  python prep-odc.py -f ./my-project --repo-url https://nexus.company.local/repository/maven-public
  python prep-odc.py -f ./my-project --repo-url https://repo1,https://repo2
  python prep-odc.py -f ./my-project --repo-url https://repo1 --repo-url https://repo2
  python prep-odc.py -f ./my-project --clean
        """,
    )
    parser.add_argument("-f", "--folder", dest="folder", required=True, help="Source code root folder")
    parser.add_argument("-o", "--output", dest="output", default="./odc-staging", help="Staging output folder (default: ./odc-staging)")
    parser.add_argument("-e", "--exclude", dest="exclude", default="", help="Comma-separated Maven GroupIDs to ignore")
    parser.add_argument("--workers", dest="workers", type=int, default=20, help="Concurrency for verification")
    parser.add_argument("--allow-snapshots", action="store_true", help="Allow -SNAPSHOT dependencies (can be flaky)")
    parser.add_argument(
        "--repo-url",
        action="append",
        default=[],
        help="Add a Maven repository URL. Can be repeated, or comma-separated.",
    )
    parser.add_argument(
        "--verify-deps-dev",
        action="store_true",
        help="Force deps.dev verification (useful for public OSS only).",
    )
    parser.add_argument(
        "--clean",
        action="store_true",
        help="Clean js-libs and java-libs folders before gathering. Default is incremental (preserve staging).",
    )
    args = parser.parse_args()

    root_path = pathlib.Path(args.folder)
    staging_path = pathlib.Path(args.output)
    js_lib_path = staging_path / "js-libs"
    java_lib_path = staging_path / "java-libs"
    generated_pom_path = staging_path / "odc-pom.xml"

    if not root_path.exists():
        log_err(f"Folder not found: {root_path}")
        return 2

    # Build on existing staging directory by default
    ensure_directory(staging_path)

    # Step 1: JS Gathering
    js_count = gather_js_files(root_path, js_lib_path, clean=args.clean)

    # Step 2: Synthetic POM Generation
    log_info("Generate a valid maven project descriptor...")
    ignored = set([x.strip() for x in args.exclude.split(",") if x.strip()]) if args.exclude else set()

    all_deps = set()
    all_props = {}
    all_repos = set()
    project_coords = set()
    pom_count = 0

    log_warn(f"Scanning {args.folder} for pom.xml files...")
    for fpath in root_path.rglob("pom.xml"):
        pom_count += 1
        d, p, repos, coords = parse_pom(fpath, ignored)
        all_deps.update(d)
        all_props.update(p)
        all_repos.update(repos)

        if coords[0] and coords[1]:
            project_coords.add((coords[0], coords[1]))

    if pom_count == 0:
        log_warn("No pom.xml files found. Skipping Java steps.")
        jar_count = 0
    else:
        print(f"    Found {len(all_deps)} unique dependencies in {pom_count} POM files.")

        filtered_deps = []
        skipped_snapshots = 0
        skipped_self = 0

        for dep in all_deps:
            g, a, v, dep_type, scope = dep

            if (g, a) in project_coords:
                skipped_self += 1
                continue

            if (not args.allow_snapshots) and str(v).endswith("-SNAPSHOT"):
                skipped_snapshots += 1
                continue

            filtered_deps.append(dep)

        if skipped_self:
            log_warn(f"Skipped {skipped_self} self-module dependencies.")
        if skipped_snapshots:
            log_warn(f"Skipped {skipped_snapshots} SNAPSHOT dependencies (use --allow-snapshots to keep them).")

        # Repositories
        custom_repos = normalize_repo_urls(args.repo_url)
        if custom_repos:
            all_repos.update(custom_repos)

        # Always include Maven Central (kept for convenience; override by passing your internal repos too)
        all_repos.add("https://repo.maven.apache.org/maven2")

        # Add Google Maven repo when com.android.tools is present
        if any(d[0] == "com.android.tools" for d in filtered_deps):
            all_repos.add(GOOGLE_MAVEN_REPO)

        # Add snapshots repo when snapshots are allowed and present
        if args.allow_snapshots and any(str(d[2]).endswith("-SNAPSHOT") for d in filtered_deps):
            all_repos.add(SONATYPE_SNAPSHOTS_REPO)

        # deps.dev verification policy:
        # - default: verify only when no custom repos were provided (OSS workflow)
        # - for internal repos: keep deps without filtering
        should_verify = args.verify_deps_dev or (not custom_repos)

        if should_verify:
            log_warn("Verifying availability on deps.dev...")
            deps_for_pom = verify_dependencies(filtered_deps, args.workers)
        else:
            log_warn("Skipping deps.dev verification (custom repo-url provided).")
            deps_for_pom = sorted(filtered_deps)

        log_warn(f"Generating synthetic POM at {generated_pom_path}...")
        generate_pom(generated_pom_path, deps_for_pom, all_props, all_repos)

        # Step 3: JAR Gathering
        jar_count = gather_jars(generated_pom_path, java_lib_path, clean=args.clean)

    print("")
    log_ok("Preparation finished:")
    print(f"    JS Files  : {js_count:<5} ({js_lib_path})")
    print(f"    JAR Files : {jar_count:<5} ({java_lib_path})")
    print(f"    Synthetic POM created at: {generated_pom_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
