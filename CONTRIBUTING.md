# Contributing to SOCloom

Thank you for your interest in contributing!

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR_USER/socloom.git`
3. Install backend: `pip install -e .` with `PYTHONPATH=backend`
4. Install frontend: `cd frontend && npm install`
5. Copy `.env.example` to `.env` and configure

## Development

```bash
# Terminal 1 — API
PYTHONPATH=backend aegis serve --reload

# Terminal 2 — Dashboard
cd frontend && npm run dev

# Terminal 3 — Demo traffic
python scripts/traffic_simulator.py
```

## Contribution Areas

- **Detection rules**: Add Sigma-style rules in `backend/aegis/detection/rules.py`
- **Skills integration**: Improve skill router in `backend/aegis/skills/registry.py`
- **MITRE mapping**: Extend technique database in `backend/aegis/mitre/mapper.py`
- **Dashboard**: React components in `frontend/src/`
- **MCP tools**: New tools in `mcp-server/server.py`

## Pull Request Guidelines

- One feature per PR
- Include tests where applicable
- Update README if adding new features
- Follow existing code style (ruff for Python)

## Code of Conduct

Be respectful. Security tooling must include authorization reminders.