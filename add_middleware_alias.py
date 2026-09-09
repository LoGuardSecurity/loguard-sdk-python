import shutil
from datetime import datetime

path = "loguard/integrations/django.py"
backup_path = f"{path}.bak_naming_alias_{datetime.now():%Y%m%d_%H%M%S}"
shutil.copy(path, backup_path)
print(f"backup: {backup_path}")

with open(path, "r", encoding="utf-8") as f:
    src = f.read()

if "LoGuardMiddleware = LogguardMiddleware" in src:
    print("SKIPPED: alias already present -- no changes made (safe to re-run)")
    raise SystemExit(0)

# Append the alias right at the end of the file -- the class is already
# fully defined by this point.
addition = '''

# Found this during a live end-to-end test run: the FastAPI integration
# calls its class "LoGuardMiddleware" (capital G), this one calls it
# "LogguardMiddleware" (lowercase g) -- the two integrations drifted
# apart at some point, no real reason for it. Not renaming the existing
# class here since that'd break anyone who already imported the old name
# -- just adding an alias so both spellings work, whichever example
# (FastAPI or Django) someone copied their code from.
LoGuardMiddleware = LogguardMiddleware
'''

src = src.rstrip("\n") + "\n" + addition
with open(path, "w", encoding="utf-8") as f:
    f.write(src)
print("OK: LoGuardMiddleware alias added for naming consistency")