# linux-nixer plugin examples

These examples speak the external scanner plugin protocol used by `linux-nixer scan --plugin PATH`.

Check a sample before using it in a real scan:

```sh
linux-nixer plugin check --plugin ./examples/plugins/shell/sample-scanner --capabilities
```

Each sample supports:

- `scan`: read a plugin request from stdin and write scan JSON to stdout.
- `capabilities`: write optional plugin metadata to stdout.

