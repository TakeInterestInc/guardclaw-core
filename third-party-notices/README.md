# Third-party notices

Full license texts for the Go modules the report helper depends on. They are copied byte for byte from the verified module cache (`go mod verify`) at the versions pinned in `go.mod`.

| Module | Version | License | Files |
|---|---|---|---|
| github.com/BobuSumisu/aho-corasick | v1.0.3 | MIT | `aho-corasick/LICENSE` |
| golang.org/x/text | v0.40.0 | BSD-3-Clause, plus Google patent grant | `golang.org-x-text/LICENSE`, `golang.org-x-text/PATENTS` |

These modules are not vendored in this repository. When you bump a version in `go.mod`, refresh these files.
