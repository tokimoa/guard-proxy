"""Tests for GoRegistryClient."""

from app.registry.go_client import GoRegistryClient


class TestEncodeModulePath:
    def test_all_lowercase(self):
        assert GoRegistryClient.encode_module_path("github.com/gin-gonic/gin") == "github.com/gin-gonic/gin"

    def test_uppercase_letters(self):
        assert GoRegistryClient.encode_module_path("github.com/Azure/azure-sdk") == "github.com/!azure/azure-sdk"

    def test_multiple_uppercase(self):
        assert GoRegistryClient.encode_module_path("github.com/BurntSushi/toml") == "github.com/!burnt!sushi/toml"

    def test_empty_string(self):
        assert GoRegistryClient.encode_module_path("") == ""

    def test_single_uppercase(self):
        assert GoRegistryClient.encode_module_path("A") == "!a"
