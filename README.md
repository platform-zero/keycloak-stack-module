# keycloak stack module

- Module id: `keycloak`
- Module repo: `keycloak-stack-module`
- Source repo: none declared
- Lifecycle: `active`

## Owned overlays
- `stack.runtime.yaml`
- `stack.config/keycloak`
- `stack.containers/keycloak`

## Dependencies
- `stack-foundation`

## Validation

```sh
./tests/validate.sh
```

## Lifecycle

`active` modules are expected to keep `stack.module.json`, owned overlays, and `tests/validate.sh` in sync.
