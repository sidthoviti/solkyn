.PHONY: install lint format test type-check all docker-build

install:
	pip install -e ".[dev]"

docker-build:
	DOCKER_DEFAULT_PLATFORM=linux/amd64 docker build -t solkyn/kali:latest -f docker/Dockerfile.kali docker/

lint:
	ruff check solkyn/ tests/

format:
	ruff format solkyn/ tests/

test:
	pytest tests/

type-check:
	mypy solkyn/

all: lint type-check test
