# Installation

AD-SecretGen is a single self-contained [PEP 723](https://peps.python.org/pep-0723/) file with two dependencies (`pycryptodome`, `rich`), and runs anywhere Python 3.11+ runs — including Linux, where DSInternals can't.

## Run it without installing (single file)

`uv` reads the inline dependency metadata and runs the script directly — even straight from its URL, nothing to clone or install:

```bash
uv run https://raw.githubusercontent.com/StrongWind1/AD-SecretGen/main/ad_secretgen.py --help
```

`uv` caches by URL, so add `--refresh` to pull a newer `main`. Or fetch it once and keep it:

```bash
wget https://raw.githubusercontent.com/StrongWind1/AD-SecretGen/main/ad_secretgen.py
uv run ad_secretgen.py --password 'P@ssw0rd!' --user alice --realm corp.local
```

## Install it with uv (recommended)

```bash
uv tool install git+https://github.com/StrongWind1/AD-SecretGen
```

That puts `ad-secretgen` (and the short alias `adsg`) on your PATH.

Run it once without installing:

```bash
uvx --from git+https://github.com/StrongWind1/AD-SecretGen ad-secretgen --help
```

## From a clone

```bash
git clone https://github.com/StrongWind1/AD-SecretGen
cd AD-SecretGen
uv sync                 # create the venv and install the package + dev tools
uv run ad-secretgen --help
```

## With pip / pipx

```bash
pipx install git+https://github.com/StrongWind1/AD-SecretGen
# or:  pip install git+https://github.com/StrongWind1/AD-SecretGen
```

## Verify

```bash
ad-secretgen --password 'P@ssw0rd!' --user alice --realm corp.local --netbios CORP
```
