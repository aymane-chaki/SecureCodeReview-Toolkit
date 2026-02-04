# SecureCodeReview-Toolkit

Small helper scripts to prep a codebase for scanning and to format OWASP Dependency Check and Semgrep JSON outputs into review-friendly tables.

## Scripts

- `prep-odc.py`
  - Stages JS files into `odc-staging/js-libs/`
  - Builds a synthetic Maven POM from all `pom.xml`
  - Downloads JARs into `odc-staging/java-libs/`
  - Supports internal repos via `--repo-url` (repeatable or comma-separated)
  - Preserves existing staging by default (`--clean` to reset)
  - Skips `-SNAPSHOT` by default (`--allow-snapshots` to keep)

- `format-odc-json.py`
  - Formats ODC JSON to a table + stats
  - Optional CSV export (`--csv`)

- `format-semgrep-json.py`
  - Formats Semgrep JSON to a table + severity distribution
  - Optional clean output without description (`--no-desc`)

## Quick usage

```bash
pip install tabulate requests

python3 prep-odc.py -f ./my-project

dependency-check.sh --project "my-project" --scan ./odc-staging/java-libs --format JSON --out odc.json
python3 format-odc-json.py odc.json --csv

semgrep scan --json-output semgrep.json
python3 format-semgrep-json.py semgrep.json --no-desc
```
