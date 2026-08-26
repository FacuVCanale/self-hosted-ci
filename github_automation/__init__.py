"""Fail-closed control-plane primitives for self-hosted GitHub automation."""

from .inventory import InventoryObservation, classify_inventory, semantic_inventory_hash
from .policy import ExecutionDecision, evaluate_execution_trust
from .registry import Registry, RegistryError, RepositoryConfig
from .gatestore import GateStore

__all__ = [
    "ExecutionDecision",
    "InventoryObservation",
    "GateStore",
    "Registry",
    "RegistryError",
    "RepositoryConfig",
    "classify_inventory",
    "evaluate_execution_trust",
    "semantic_inventory_hash",
]
