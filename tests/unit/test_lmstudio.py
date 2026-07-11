"""Unit tests for LM Studio CLI integration."""

from __future__ import annotations

import os
from unittest.mock import patch

from solkyn.llm.lmstudio import get_model_from_env, is_lm_studio_provider


class TestIsLmStudioProvider:
    def test_lm_studio_base(self):
        assert is_lm_studio_provider("lm-studio")

    def test_lm_studio_apex(self):
        assert is_lm_studio_provider("lm-studio-apex")

    def test_lm_studio_gemma(self):
        assert is_lm_studio_provider("lm-studio-gemma4")

    def test_openai(self):
        assert not is_lm_studio_provider("openai")

    def test_anthropic(self):
        assert not is_lm_studio_provider("anthropic")

    def test_ollama(self):
        assert not is_lm_studio_provider("ollama")


class TestGetModelFromEnv:
    def test_returns_model_when_set(self):
        with patch.dict(os.environ, {"LM_STUDIO_MODEL": "bugtraceai-apex-g4-26b"}):
            assert get_model_from_env() == "bugtraceai-apex-g4-26b"

    def test_returns_none_when_unset(self):
        env = os.environ.copy()
        env.pop("LM_STUDIO_MODEL", None)
        with patch.dict(os.environ, env, clear=True):
            assert get_model_from_env() is None
