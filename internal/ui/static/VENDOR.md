# Vendored assets

The web UI ships without a build step, so its two dependencies are checked in
here and served from the binary via `embed`. No CDN is contacted at run time —
the UI works on a machine with no network access, which is the point of a local
audit tool.

| File           | Project  | Version | License |
|----------------|----------|---------|---------|
| `pico.min.css` | Pico CSS | 2.0.6   | MIT     |
| `htmx.min.js`  | htmx     | 2.0.4   | 0BSD    |

To update, replace the file and the version above; there is nothing else to do.
