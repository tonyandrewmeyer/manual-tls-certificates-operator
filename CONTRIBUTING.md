# Contributing

## Developing

Create and activate a virtualenv with the development requirements:

    virtualenv -p python3 venv
    source venv/bin/activate


## Testing

### Unit tests

```bash
tox -e unit
```

### Scenario tests

```bash
tox -e scenario
```

### Static analysis

```bash
tox -e static
```

### Linting

```bash
tox -e lint
```
