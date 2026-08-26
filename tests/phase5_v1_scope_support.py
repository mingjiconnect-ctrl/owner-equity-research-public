from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from phase4a_support import replace_graph
from phase4e2_support import complete_phase4e_graph
from test_phase4e1_research_bundle_builder import _completed_graph

from owner_research.owner_equity_types import build_research_source_index
from owner_research.research_bundle_artifacts import write_research_bundle_artifacts
from owner_research.research_bundle_builder import build_research_bundle
from owner_research.research_report import reload_research_input
from owner_research.validation import ContractGraph


def formal_scope_graph(
    sample_payloads,
    *,
    security_structure: str = "single_primary_common",
) -> ContractGraph:
    graph = complete_phase4e_graph(sample_payloads)
    base = graph.facts[0]
    scope_facts = (
        replace(
            base,
            fact_id="fact:acme:scope:mic",
            concept="security_mic",
            value_type="text",
            value="XNYS",
            unit=None,
            currency=None,
            source_locator="10-K cover: exchange",
        ),
        replace(
            base,
            fact_id="fact:acme:scope:share-class",
            concept="security_share_class",
            value_type="text",
            value="common",
            unit=None,
            currency=None,
            source_locator="10-K cover: title of class",
        ),
        replace(
            base,
            fact_id="fact:acme:scope:structure",
            concept="security_structure",
            value_type="text",
            value=security_structure,
            unit=None,
            currency=None,
            source_locator="10-K cover: registered security structure",
        ),
        replace(
            base,
            fact_id="fact:acme:scope:sic",
            concept="sec_sic_code",
            value_type="number",
            value=3571,
            unit="count",
            currency=None,
            source_locator="SEC filing header: SIC",
        ),
    )
    return replace_graph(graph, facts=(*graph.facts, *scope_facts))


def typed_research_inputs_for_graph(graph: ContractGraph, output_directory: Path):
    bundle = build_research_bundle(graph, run_id=graph.manifests[0].run_id)
    completed = _completed_graph(graph, bundle)
    write_research_bundle_artifacts(
        completed,
        bundle,
        output_directory=output_directory,
    )
    research_input = reload_research_input(output_directory, graph=completed)
    source_index = build_research_source_index(graph=completed, research=bundle)
    return research_input, source_index
