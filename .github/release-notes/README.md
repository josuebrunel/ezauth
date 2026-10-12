# Release notes

Each release has its own summary here, named after its tag: `v0.31.0.md` for
the `v0.31.0` tag. The release workflow puts that file at the top of the
GitHub release, above the commit list GoReleaser writes.

Add the file **before you push the tag**. The workflow stops with a clear error
if it's missing, so a release can't quietly reuse the text of an older one (that
happened to v0.30.1 and v0.30.2, which both shipped the v0.30.0 summary).
