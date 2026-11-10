# Isolate the evaluation freezer from user package discovery

The first Windows build on4 November2026 produced a wheel/source archive, then PyInstaller
6.22.3 failed in its binary parent-directory preservation helper. That helper unconditionally
appended site.getusersitepackages(), even with Python isolated mode active, and attempted
to stat an inaccessible roaming user package directory outside Product. No candidate passed.
The failed directory/logs are retained. No global site, ACL or security policy was changed.

The reviewed spec now verifies sys.prefix is Product/.venv and sets only the build process's
cached site.USER_SITE value to that same approved environment's site-packages. The helper
therefore examines the already-approved project environment instead of an unrelated user
directory. This does not grant access to the denied directory, change permissions, modify
installed dependency code, add global configuration or affect the shipped runtime. Revalidate
this narrow compatibility adjustment after changing Python or PyInstaller.

Each build creates a fresh ignored work/candidate directory; prior attempts are never replaced.
The spec uses separate CLI and GUI analyses with one shared COLLECT folder. This keeps Qt/AI
entry hooks out of the console process and deduplicates common native runtime files. Both
executables are asInvoker. No signing, collector, private GUI startup, privileged lab action,
remote repository or publication is implied by local evaluation packaging.

The source archive explicitly includes reviewed scripts, packaging recipes, engineering docs,
tests and invented examples, while excluding private work, environments, secrets and real cases.
The portable runtime excludes lab helpers/tests. Artifact membership and source/resource hashes
must be inspected; source tests alone do not validate the final executable.
