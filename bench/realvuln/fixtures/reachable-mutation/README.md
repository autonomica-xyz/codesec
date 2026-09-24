Unscored fixture (P06 task 9). The planted mutation is the `eval(name)`
sink at app.py:14, reachable unauthenticated from GET /run/<name>.
Expected: any functional arm reports a code-execution finding at app.py
lines 13-15 and a static reachable trace whose final frame sits at the
sink. Used in calibration only; never part of scored bundles.
