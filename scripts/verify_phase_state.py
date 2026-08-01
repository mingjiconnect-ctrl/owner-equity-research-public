#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

try:
    from scripts.public_bootstrap import commit_exists, verify_public_bootstrap_snapshot
except ModuleNotFoundError:  # Direct ``python -I scripts/...`` execution.
    from public_bootstrap import commit_exists, verify_public_bootstrap_snapshot

ROOT = Path(__file__).resolve().parents[1]

PHASE5C0_CLOSEOUT = {
    "phase": "Phase 5C-0.1",
    "substantive_pull_request": 35,
    "substantive_head_commit": "39f0ba6d941a293dd3d499b6f0e20ec78468ed8b",
    "substantive_merge_commit": "3e7d2f946e874d75370bbb825e36ef6f2800de92",
    "substantive_tree_sha": "bf710a1ec542f669d79d0f0869b231444ae75957",
    "pr_ci_run_id": "29263567473",
    "main_ci_run_id": "29263865584",
    "audit": {
        "tool": "owner-research-phase5c-readonly",
        "version": "2.1.0",
        "reviewed_commit": "39f0ba6d941a293dd3d499b6f0e20ec78468ed8b",
        "canonical_report_sha256": (
            "945efb3878c624738bccb49f317da4bffb1a9cc2b7f98edef61002d229c09b3b"
        ),
        "artifact_sha256": (
            "e3d4c60149bfb8194e8df7a98c739bfc9776696d3bb3a40457d02e71d9f40de9"
        ),
    },
}

PHASE5C1_CLOSEOUT = {
    "phase": "Phase 5C-1",
    "substantive_pull_request": 38,
    "substantive_head_commit": "78ed0565f5456c2438b77622596bbc26228c4114",
    "substantive_merge_commit": "34ef5b1463c2b29f87399846ef0bcc206eb2f52c",
    "substantive_tree_sha": "9033f179e6584d09a5191601f555c57a86215a3e",
    "pr_ci_run_id": "29268633764",
    "main_ci_run_id": "29268975345",
    "audit": {
        "tool": "owner-research-phase5c-readonly",
        "version": "2.1.1",
        "reviewed_commit": "34ef5b1463c2b29f87399846ef0bcc206eb2f52c",
        "canonical_report_sha256": (
            "99b89ea09782728fb697d2d46d895b14e57aa905b5691829b0d0339e187f8ada"
        ),
        "artifact_sha256": (
            "eec986a3c38ed559bfe5ccddecd4479c3c05a6ba5cac0fa6454d2e5359b13aaa"
        ),
    },
}

PHASE5C2_CLOSEOUT = {
    "phase": "Phase 5C-2",
    "substantive_pull_request": 39,
    "substantive_head_commit": "ea0283695f9c65fa1375f3eda6a822ee685f4d6a",
    "substantive_merge_commit": "2d8d900fa5244f9afb16fe28e9da4d4db6c448c1",
    "substantive_tree_sha": "1d0bcdcb982c5fbb86ec307378a77b1d8066a3d4",
    "pr_ci_run_id": "29270210886",
    "main_ci_run_id": "29270484340",
    "audit": {
        "tool": "owner-research-phase5c-readonly",
        "version": "2.1.2",
        "reviewed_commit": "2d8d900fa5244f9afb16fe28e9da4d4db6c448c1",
        "canonical_report_sha256": (
            "5b9cb550b8efc9efd7db6ea6e5f527c69e368cc0f3c6c43c963543bfd74d29f4"
        ),
        "artifact_sha256": (
            "1fc481c0a81a2d9c8ec9902a45b74f07171963ef71a48883a84ace41e5442746"
        ),
    },
}

PHASE5C3_CLOSEOUT = {
    "phase": "Phase 5C-3",
    "substantive_pull_request": 40,
    "substantive_head_commit": "48879ad1bc9b37a9480e7f4c62324452ff82380b",
    "substantive_merge_commit": "a6c6d85ae0621adab889a4f4da33eedd035cbe33",
    "substantive_tree_sha": "aee0e38ed5afda7de149474396a19a5c2c4fbf31",
    "pr_ci_run_id": "29271567120",
    "main_ci_run_id": "29271863942",
    "audit": {
        "tool": "owner-research-phase5c-readonly",
        "version": "2.1.3",
        "reviewed_commit": "a6c6d85ae0621adab889a4f4da33eedd035cbe33",
        "canonical_report_sha256": (
            "b3606120c377f66aa0654d81fe0131e98f08123b284647d79afd6f5c752759b8"
        ),
        "artifact_sha256": (
            "d577022467114515d613a8c990889f5e7f8929d813df9da571b2840d4eb865e2"
        ),
    },
}

PHASE5C4_CLOSEOUT = {
    "phase": "Phase 5C-4",
    "substantive_pull_request": 41,
    "substantive_head_commit": "6dcbb8efc0e15a7395081686af46524682770ee8",
    "substantive_merge_commit": "f16595e50f6d3e946f990edd3d3cbc9fd51ff82b",
    "substantive_tree_sha": "f996dc614236ef96e3bd144f659857fb6a0927a9",
    "pr_ci_run_id": "29273078782",
    "main_ci_run_id": "29273390412",
    "audit": {
        "tool": "owner-research-phase5c-readonly",
        "version": "2.1.4",
        "reviewed_commit": "f16595e50f6d3e946f990edd3d3cbc9fd51ff82b",
        "canonical_report_sha256": (
            "0a3b6e5321646a798220144aebd40ab808d45c0b8c748fcd06160bbb5e1ee86a"
        ),
        "artifact_sha256": (
            "1a0e93a1221689fad3aa63b299716139b43408ea14ac99c7fce158e2fa8da2ff"
        ),
    },
}

PHASE5C5_CLOSEOUT = {
    "phase": "Phase 5C-5",
    "substantive_pull_request": 42,
    "substantive_head_commit": "9e53ced8e8af6f8973573c063f628a1a93a57949",
    "substantive_merge_commit": "0ad92bb3206b895e966fa8ad2db7cc25406c6fc9",
    "substantive_tree_sha": "61056e8bb69269a4fdde0ddb981bf8cc8417f22c",
    "pr_ci_run_id": "29274521822",
    "main_ci_run_id": "29274820514",
    "audit": {
        "tool": "owner-research-phase5c-readonly",
        "version": "2.1.5",
        "reviewed_commit": "0ad92bb3206b895e966fa8ad2db7cc25406c6fc9",
        "canonical_report_sha256": (
            "563ecb53db068a33c7996dc9f413fed1247e2665c3e196410edb10d2a021656c"
        ),
        "artifact_sha256": (
            "9b2e9bd5d3e34f4d7569621b24de534a1e8b837637b1a8105fda58b719b22556"
        ),
    },
}

PHASE5D0_CLOSEOUT = {
    "phase": "Phase 5D-0",
    "substantive_pull_request": 44,
    "substantive_head_commit": "5c66977c78c66a968f9f89baf7ff3dc2069fdd8f",
    "substantive_merge_commit": "4814029d9c5a690e2779dcb4e5e800798c663053",
    "substantive_tree_sha": "0a09817699f450ab014b291dbe544c3cd133eea7",
    "pr_ci_run_id": "29295535892",
    "main_ci_run_id": "29295736044",
    "audit": {
        "tool": "owner-research-phase5d-readonly",
        "version": "2.2.0",
        "reviewed_commit": "5c66977c78c66a968f9f89baf7ff3dc2069fdd8f",
        "canonical_report_sha256": (
            "b50c413b967c8c9def7f1c81ff9e839142b1c84424bb007b296d3aeb84a3d24e"
        ),
        "artifact_sha256": (
            "d244891cfeb05e887bc5dba15a0ffdc33ded5958e48539e4cfb52cce12630ea0"
        ),
    },
}

PHASE5D1_CLOSEOUT = {
    "phase": "Phase 5D-1",
    "implementation_pull_request": 46,
    "implementation_head_commit": "f5634092c1bc18e4f28eab9eaea838905b7088fb",
    "implementation_merge_commit": "8d921cc71ff864e53223add50502d9110d571aab",
    "acceptance_pull_request": 47,
    "substantive_pull_request": 47,
    "substantive_head_commit": "f72fcf10e06b8b6c7bba6d5fe036d5b02d61af10",
    "substantive_merge_commit": "7c13073aa70aa5f83192b4a52b7967b8556c57bb",
    "substantive_tree_sha": "9f9210cbe92f5fd0f96c188fa1490ba66ee164d7",
    "pr_ci_run_id": "29297240179",
    "main_ci_run_id": "29297468611",
    "audit": {
        "tool": "owner-research-phase5d-readonly",
        "version": "2.2.1",
        "reviewed_commit": "f72fcf10e06b8b6c7bba6d5fe036d5b02d61af10",
        "canonical_report_sha256": (
            "caffe60d592660d8d9457743c0b2a4b1383567d11288b100836d9e97b997beb5"
        ),
        "artifact_sha256": (
            "571cb3308f4d92995801cdf1d629ee1ce0f2229ed3f442202e34b1165cb87969"
        ),
    },
}

PHASE5D2_CLOSEOUT = {
    "phase": "Phase 5D-2",
    "substantive_pull_request": 49,
    "substantive_head_commit": "4c03b4931ad78accb4e62b3b16da31ee30efe105",
    "substantive_merge_commit": "43fffa76d3eb863d05fdd0c6eb99adac69209429",
    "substantive_tree_sha": "7259ba2dce9f7bde58f291daf3645f4a6fd352f0",
    "pr_ci_run_id": "29298850019",
    "main_ci_run_id": "29299088854",
    "audit": {
        "tool": "owner-research-phase5d-readonly",
        "version": "2.2.2",
        "reviewed_commit": "4c03b4931ad78accb4e62b3b16da31ee30efe105",
        "canonical_report_sha256": (
            "ba49b7241a1f95527d45b4a1b32aba88b148dc14c691d0734a0baaa1ba73e1ac"
        ),
        "artifact_sha256": (
            "880cb4463284425c5eea9289c7725223b2a0f8fb34b8810820006bf1cd27458b"
        ),
    },
}

PHASE5D3_CLOSEOUT = {
    "phase": "Phase 5D-3",
    "substantive_pull_request": 51,
    "substantive_head_commit": "02ecfc5e5f8c4cafee98d7410e5eb141d41c8fea",
    "substantive_merge_commit": "dcbc5d5bbbb6a798b294471c1d63f6a298d636cf",
    "substantive_tree_sha": "3e833db7b084aa6e2009323bd94ce93c1db391d2",
    "pr_ci_run_id": "29300427055",
    "main_ci_run_id": "29300664978",
    "audit": {
        "tool": "owner-research-phase5d-readonly",
        "version": "2.2.3",
        "reviewed_commit": "02ecfc5e5f8c4cafee98d7410e5eb141d41c8fea",
        "canonical_report_sha256": (
            "4d46293693a3afc984d75825d53d65c166e44cd9f59e39282c7e50f32a0990a0"
        ),
        "artifact_sha256": (
            "6a5a6162868b7f3e7a98593c0ec09a38ef38de7a66e869b48f7fa7c64c0cc6cd"
        ),
    },
}

PHASE5D4_CLOSEOUT = {
    "phase": "Phase 5D-4",
    "substantive_pull_request": 53,
    "substantive_head_commit": "50aa4fc51f30abe1b1cc2cd8bfd7b83f9f5821f2",
    "substantive_merge_commit": "e3ef484f42cae9ad78f8827857fc8e79bcd1d514",
    "substantive_tree_sha": "8bcc8f5875534fc9f07c87aa711d4e18208995db",
    "pr_ci_run_id": "29301896045",
    "main_ci_run_id": "29302120207",
    "audit": {
        "tool": "owner-research-phase5d-readonly",
        "version": "2.2.4",
        "reviewed_commit": "50aa4fc51f30abe1b1cc2cd8bfd7b83f9f5821f2",
        "canonical_report_sha256": (
            "9fc13fbb5fcfc9f454f63218d962b31b9f8ef090db03e25e06ca9a333b97be11"
        ),
        "artifact_sha256": (
            "8a0714a16e11195cb156999e5d11f727ef36b8ec3474d8fc293966eda9b693fe"
        ),
    },
}

PHASE5D5_CLOSEOUT = {
    "phase": "Phase 5D-5",
    "substantive_pull_request": 55,
    "substantive_head_commit": "7bad2bd3a0e980fd9724053538c9612201984c8f",
    "substantive_merge_commit": "a63e3dcb5c57ce3827fbb26a75742e6c352abb30",
    "substantive_tree_sha": "c6fa9da7b729209a39b53445aaa0684051b2992b",
    "pr_ci_run_id": "29303501317",
    "main_ci_run_id": "29303730712",
    "audit": {
        "tool": "owner-research-phase5d-readonly",
        "version": "2.2.5",
        "reviewed_commit": "7bad2bd3a0e980fd9724053538c9612201984c8f",
        "canonical_report_sha256": (
            "0d5ed41c3bd5c1a1a91cc923767618679fad20d372d486a5a0367b48963128c4"
        ),
        "artifact_sha256": (
            "bd68c1fa4ff92b5f0766e4cb4e5c4688f5c71098b61a685a4b203f2093d67ccb"
        ),
    },
}

PHASE5D6_CLOSEOUT = {
    "phase": "Phase 5D-6",
    "substantive_pull_request": 57,
    "substantive_head_commit": "8b691157b4cef0c35ae9df74445c44b216f01933",
    "substantive_merge_commit": "38be7b66ea20c5d148054750f67b98bb010c00d4",
    "substantive_tree_sha": "1bca5c5d15e6d404f6ea076bb740d9011319fdc5",
    "pr_ci_run_id": "29304981445",
    "main_ci_run_id": "29305219309",
    "audit": {
        "tool": "owner-research-phase5d-readonly",
        "version": "2.2.6",
        "reviewed_commit": "8b691157b4cef0c35ae9df74445c44b216f01933",
        "canonical_report_sha256": (
            "cbaab5d1b2b3c0f8a7fd4c9bfa7d702c01befee318373f681f11260b5dfdfde9"
        ),
        "artifact_sha256": (
            "70cb30a40561396b8522b0b5e5f79f66be312fed0dace75ff3a00e2098afaaaf"
        ),
    },
}

PHASE5E2A1_CLOSEOUT = {
    "phase": "Phase 5E-2A.1",
    "substantive_pull_request": 63,
    "substantive_head_commit": "280d9d60c3caf8d29bfe11729b0ae4f99d20e43e",
    "substantive_merge_commit": "945834597553bb8ff4df12d77c402bee0433e572",
    "substantive_tree_sha": "9799545e114080056ac2091c2206400342247ba1",
    "pr_ci_run_id": "29344996417",
    "main_ci_run_id": "29345441770",
    "audit": {
        "tool": "owner-research-phase5e-readonly",
        "version": "2.3.2.1",
        "reviewed_commit": "945834597553bb8ff4df12d77c402bee0433e572",
        "canonical_report_sha256": (
            "b6cbf9a6d3b1e8bcb752de235ecb02447260c25cc96f76e712429e3e1c7485ab"
        ),
        "artifact_sha256": (
            "845752d3f507c09e4b97ea63fa959c6c582026440a7f61858b26b217100ef25f"
        ),
    },
}

PHASE5E2A2_CLOSEOUT = {
    "phase": "Phase 5E-2A.2",
    "implementation_pull_request": 65,
    "substantive_pull_request": 65,
    "substantive_head_commit": "814574e58bb40be2b174d1f88a270f4966978f1e",
    "substantive_merge_commit": "78304ba7923fbcaf706e241223090d31798a43af",
    "substantive_tree_sha": "153d04ccbf6a35d9bbd66cfee0193373fca0374f",
    "pr_ci_run_id": "29391177190",
    "main_ci_run_id": "29391454012",
    "audit": {
        "tool": "owner-research-phase5e-readonly",
        "version": "2.3.2.2",
        "reviewed_commit": "78304ba7923fbcaf706e241223090d31798a43af",
        "canonical_report_sha256": (
            "bec9348c2d8eae0e669220c4bc3f0365f2ba16ed833e8b149d7d47f973e649a4"
        ),
        "artifact_sha256": (
            "d96752824074280c19fb1cbc3d95f4d5f12e6d25f60208a308366f8bf2fc8512"
        ),
        "actions_artifact_zip_sha256": (
            "52db96f0fd13929df9e54b4d6ac52b7a67408b42628a84c73e0988cdb138cfb3"
        ),
        "test_counts": {"collected": 853, "passed": 853, "skipped": 0, "failed": 0},
        "finding_counts": {"P0": 0, "P1": 0, "P2": 0, "P3": 0},
    },
    "kernel_release": {
        "tag": "v2.0.0-rc.2",
        "annotated_tag_object": "4e19ce6a59bc4321ebcd368e807ed764f4e8abde",
        "commit": "be9b0773d5a78f5f8a33ba982494512668df85fe",
        "tag_ci_run_id": "29388946546",
    },
    "component_lock_sha256": (
        "b6def83a8f87c09966a5f5b8f7d178c0dd3785be13d7a1cb60346a5b82846564"
    ),
    "market_reference_snapshot_schema_sha256": (
        "cdadc1a1f27b52fef933ce46e0ec901e7b95f0cb7bcbc0d2d55860c470a8824e"
    ),
    "public_schema_count": 43,
}

PHASE5E2A21_CLOSEOUT = {
    "phase": "Phase 5E-2A.2.1",
    "implementation_pull_request": 67,
    "substantive_pull_request": 67,
    "substantive_head_commit": "00e2b3492689debe720c833d84be7347ac40c854",
    "substantive_merge_commit": "973a98a8e8b03ba1f8efa681b8c528c064467a2c",
    "substantive_tree_sha": "6d213403f93895b397315999211e0386bb248b71",
    "pr_ci_run_id": "29404842547",
    "main_ci_run_id": "29405235491",
    "audit": {
        "tool": "owner-research-phase5e-readonly",
        "version": "2.3.2.2.1",
        "reviewed_commit": "973a98a8e8b03ba1f8efa681b8c528c064467a2c",
        "canonical_report_sha256": (
            "d7ad6db8980c5804f155362458550039ff41ed68b42d6c75dd342346babb9315"
        ),
        "artifact_sha256": ("4ef80adc3da2bc3988c64941f434aff4d7fe9b6fc50895e3708951ab8ef52ffb"),
        "actions_artifact_zip_sha256": (
            "e62f7a4a704ee7389cf409be401724f60b6be226330ab685603553c9462a555c"
        ),
        "test_counts": {"collected": 866, "passed": 866, "skipped": 0, "failed": 0},
        "finding_counts": {"P0": 0, "P1": 0, "P2": 0, "P3": 0},
    },
    "kernel_release": {
        "tag": "v2.0.0-rc.2",
        "annotated_tag_object": "4e19ce6a59bc4321ebcd368e807ed764f4e8abde",
        "commit": "be9b0773d5a78f5f8a33ba982494512668df85fe",
        "tag_ci_run_id": "29388946546",
    },
    "component_lock_sha256": ("664ad0f5717248c8a1a748e54a0ec1eb4c5d135acfd9d701d0aefe1e499c14b6"),
    "market_reference_snapshot_schema_sha256": (
        "cdadc1a1f27b52fef933ce46e0ec901e7b95f0cb7bcbc0d2d55860c470a8824e"
    ),
    "public_schema_count": 43,
}

PHASE5E2B_CLOSEOUT = {
    "phase": "Phase 5E-2B",
    "implementation_pull_request": 69,
    "substantive_pull_request": 69,
    "substantive_head_commit": "2b9618f39eef99820cc03690b0d21e44d00dddac",
    "substantive_merge_commit": "8e9d1f5e233c3d73cbcb97952c915d7f784e8970",
    "substantive_tree_sha": "ff650c4503789eb1c434f34d5859b818c333f639",
    "pr_ci_run_id": "29426797627",
    "main_ci_run_id": "29427291815",
    "audit": {
        "tool": "owner-research-phase5e-readonly",
        "version": "2.3.2.3",
        "reviewed_commit": "8e9d1f5e233c3d73cbcb97952c915d7f784e8970",
        "canonical_report_sha256": (
            "ad5a1c180c9a267e70a7c92b302935661ca499cf54cddf6c25209353ce8d6954"
        ),
        "artifact_sha256": (
            "573376729d90f83e49a337bfca1272c0a2e2389ede44f17329fdcae0d2b01141"
        ),
        "test_counts": {"collected": 877, "passed": 877, "skipped": 0, "failed": 0},
        "finding_counts": {"P0": 0, "P1": 0, "P2": 0, "P3": 0},
    },
    "kernel_release": {
        "tag": "v2.0.0-rc.2",
        "annotated_tag_object": "4e19ce6a59bc4321ebcd368e807ed764f4e8abde",
        "commit": "be9b0773d5a78f5f8a33ba982494512668df85fe",
        "tag_ci_run_id": "29388946546",
    },
    "component_lock_sha256": (
        "957c43bf4b9cca4f2168e816b5ea89b9ca7d86bdad5d967cc8de76e38bfdf1c7"
    ),
    "market_reference_snapshot_schema_sha256": (
        "cdadc1a1f27b52fef933ce46e0ec901e7b95f0cb7bcbc0d2d55860c470a8824e"
    ),
    "public_schema_count": 43,
}

PHASE5E2B1_CLOSEOUT = {
    "phase": "Phase 5E-2B.1-0",
    "kind": "corrective_semantic_policy_closeout",
    "baseline_commit": "1449e544d9907297c43c8d930d33170c45a60abb",
    "historical_phase5e2b_closeout": PHASE5E2B_CLOSEOUT,
    "independent_semantic_finding": {
        "finding_id": "P5E-F038",
        "priority": "P0",
        "status": "corrective_implementation_required",
        "summary": (
            "Cross-source disclosures of one completed share event can be consumed more than "
            "once."
        ),
        "red_fixture_sha256": (
            "758ea5faa1d8b0eb095343fc9812964911b53aa1870d513339a324bb6869a548"
        ),
        "baseline_reproducer": "scripts/verify_phase5e2b1_cross_source_red.py",
    },
    "audit": {
        "tool": "owner-research-phase5e-readonly",
        "version": "2.3.2.3.1",
        "required_finding_counts": {"P0": 0, "P1": 0, "P2": 0, "P3": 0},
    },
    "kernel_release": PHASE5E2B_CLOSEOUT["kernel_release"],
    "component_lock_sha256": PHASE5E2B_CLOSEOUT["component_lock_sha256"],
    "market_reference_snapshot_schema_sha256": PHASE5E2B_CLOSEOUT[
        "market_reference_snapshot_schema_sha256"
    ],
    "public_schema_count": 43,
}

PHASE5E2B11_IMPLEMENTATION = {
    "phase": "Phase 5E-2B.1-1",
    "implementation_pull_request": 72,
    "substantive_pull_request": 72,
    "substantive_head_commit": "527a18e19ff164325dc310f8dc3da547e5519769",
    "substantive_merge_commit": "11e8ba904bee27fd247ca4f6f9ae5194ba24897a",
    "substantive_tree_sha": "70609764d5710a137d4555ca86cf7b793263548e",
    "pr_ci_run_id": "29481851736",
    "main_ci_run_id": "29482340802",
    "audit": {
        "tool": "owner-research-phase5e-readonly",
        "version": "2.3.2.3.2",
        "reviewed_commit": "11e8ba904bee27fd247ca4f6f9ae5194ba24897a",
        "canonical_report_sha256": (
            "670cc6b66c9d178511c6e546c7b8b93af75eb6d5f16a94257b4f49337a152415"
        ),
        "artifact_sha256": (
            "dc930942fc3cdc47230317e0db6fa1aefe0ebfa22fbc73df11966147d2147451"
        ),
        "audit_evidence_sha256": (
            "a0884e96b7ca394591713bd9aa66c399df49ad1c418a9386e112521962418bde"
        ),
        "test_counts": {"collected": 897, "passed": 897, "skipped": 0, "failed": 0},
        "finding_counts": {"P0": 0, "P1": 0, "P2": 0, "P3": 0},
    },
}

PHASE5E2B11_CLOSEOUT = {
    "phase": "Phase 5E-2B.1-1",
    "kind": "corrective_semantic_implementation_acceptance",
    "policy_closeout": PHASE5E2B1_CLOSEOUT,
    "implementation": PHASE5E2B11_IMPLEMENTATION,
    "kernel_release": PHASE5E2B_CLOSEOUT["kernel_release"],
    "component_lock_sha256": PHASE5E2B_CLOSEOUT["component_lock_sha256"],
    "market_reference_snapshot_schema_sha256": PHASE5E2B_CLOSEOUT[
        "market_reference_snapshot_schema_sha256"
    ],
    "public_schema_count": 43,
}


def _tree(commit: str) -> str:
    return subprocess.check_output(
        ["git", "-C", str(ROOT), "rev-parse", f"{commit}^{{tree}}"],
        text=True,
    ).strip()


def _verify_phase5e2b12a_acceptance_topology(
    acceptance_closeout: Path,
) -> None:
    relative_closeout = str(acceptance_closeout.relative_to(ROOT))
    introducing = subprocess.check_output(
        [
            "git",
            "-C",
            str(ROOT),
            "log",
            "--full-history",
            "--no-merges",
            "--diff-filter=A",
            "--format=%H",
            "--",
            relative_closeout,
        ],
        text=True,
    ).splitlines()
    if len(introducing) != 1:
        raise SystemExit("2A acceptance closeout introduction is ambiguous")
    introduction = introducing[0]
    introduction_parents = subprocess.check_output(
        ["git", "-C", str(ROOT), "show", "-s", "--format=%P", introduction],
        text=True,
    ).split()
    if len(introduction_parents) != 1:
        raise SystemExit("2A acceptance closeout must be introduced by one direct commit")
    introduction_parent = introduction_parents[0]
    changed_entries = subprocess.check_output(
        [
            "git",
            "-C",
            str(ROOT),
            "diff-tree",
            "--no-commit-id",
            "--name-status",
            "--no-renames",
            "-r",
            introduction_parent,
            introduction,
        ],
        text=True,
    ).splitlines()
    expected_entries = {
        "A\tdocs/phase5e2b12a-acceptance-closeout.json",
        "M\tdocs/phase-status.json",
    }
    if set(changed_entries) != expected_entries or len(changed_entries) != len(
        expected_entries
    ):
        raise SystemExit("2A acceptance closeout commit is not the exact two-file patch")

    head = subprocess.check_output(
        ["git", "-C", str(ROOT), "rev-parse", "HEAD"],
        text=True,
    ).strip()
    if head == introduction:
        return

    acceptance_merges: list[tuple[str, list[str]]] = []
    first_parent_history = subprocess.check_output(
        ["git", "-C", str(ROOT), "rev-list", "--first-parent", "--parents", "HEAD"],
        text=True,
    ).splitlines()
    for entry in first_parent_history:
        commit, *parents = entry.split()
        if len(parents) == 2 and parents[1] == introduction:
            acceptance_merges.append((commit, parents))
    if len(acceptance_merges) != 1:
        raise SystemExit("accepted Phase 5E-2B.1-2A PR merge is missing or ambiguous")
    acceptance_merge, merge_parents = acceptance_merges[0]
    if (
        merge_parents[0] != introduction_parent
        or _tree(acceptance_merge) != _tree(introduction)
    ):
        raise SystemExit("accepted Phase 5E-2B.1-2A merge topology is invalid")


def _verify_recorded_closeout_tree(
    closeout: dict[str, object],
    *,
    public_snapshot_verified: bool = False,
) -> None:
    head = str(closeout["substantive_head_commit"])
    merge = str(closeout["substantive_merge_commit"])
    recorded_tree = str(closeout["substantive_tree_sha"])
    if commit_exists(head, ROOT) and commit_exists(merge, ROOT):
        head_tree = _tree(head)
        merge_tree = _tree(merge)
        if head_tree != recorded_tree or merge_tree != head_tree:
            raise SystemExit(f"{closeout['phase']} commits do not resolve to the recorded tree")
        return
    # The clean public repository deliberately omits the private commit graph.
    # Its immutable root snapshot content-addresses the phase ledger that
    # contains these historical commit/tree records.
    if not public_snapshot_verified:
        verify_public_bootstrap_snapshot(ROOT)
    if not all(
        isinstance(value, str)
        and len(value) == 40
        and all(character in "0123456789abcdef" for character in value)
        for value in (head, merge, recorded_tree)
    ):
        raise SystemExit(f"{closeout['phase']} external closeout identity is malformed")


def _successor_subprocess_path() -> str:
    child_path = "/usr/bin:/bin:/usr/sbin:/sbin"
    if os.environ.get("AUDIT_CANDIDATE_SANDBOX") == "linux-pivot-root-netless-v1":
        child_path = os.environ.get("PATH", "")
        if child_path != "/audit-bin:/venv/bin:/usr/bin:/bin":
            raise SystemExit("successor position audit Git-shim path is not the sealed runtime")
    return child_path


def _resolve_successor_position(ref: str) -> dict[str, object]:
    """Resolve recursive successor state without importing a mutable module."""

    verifier = ROOT / "scripts" / "verify_phase5e_successor_gate.py"
    child_path = _successor_subprocess_path()
    try:
        completed = subprocess.run(
            [
                sys.executable,
                "-I",
                str(verifier),
                "--repository",
                str(ROOT),
                "--describe-position-ref",
                ref,
            ],
            cwd="/",
            env={"PATH": child_path},
            capture_output=True,
            check=False,
            timeout=120,
        )
    except subprocess.TimeoutExpired as exc:
        raise SystemExit("successor position resolution exceeded its fixed timeout") from exc
    if completed.returncode != 0:
        message = completed.stderr.decode("utf-8", errors="replace").strip()
        raise SystemExit(f"successor position resolution failed: {message}")

    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        value: dict[str, object] = {}
        for key, child in pairs:
            if key in value:
                raise ValueError(f"duplicate JSON key: {key}")
            value[key] = child
        return value

    try:
        position = json.loads(
            completed.stdout.decode("utf-8"),
            object_pairs_hook=reject_duplicates,
            parse_constant=lambda token: (_ for _ in ()).throw(
                ValueError(f"non-finite JSON constant: {token}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise SystemExit("successor position output is not strict JSON") from exc
    expected_bytes = (
        json.dumps(position, allow_nan=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()
    if (
        not isinstance(position, dict)
        or set(position) != {"authority", "bundle", "depth", "gate_id", "stage"}
        or completed.stdout != expected_bytes
    ):
        raise SystemExit("successor position output has an open or noncanonical shape")
    return position


def _expected_phase_state(
    *,
    stage: str | None = None,
    accepted: bool | None = None,
    successor_position: dict[str, object] | None = None,
) -> dict:
    if stage is None:
        if accepted is None:
            raise TypeError("stage or accepted must be provided")
        stage = "2a_accepted" if accepted else "2a_pending"
    elif accepted is not None:
        raise TypeError("stage and accepted are mutually exclusive")
    expected = {
        "schema_version": "2.0.0",
        "current_phase": "Phase 5E-2B.1",
        "status": "implementation_complete_pending_acceptance",
        "prior_closeouts": [
            PHASE5C0_CLOSEOUT,
            PHASE5C1_CLOSEOUT,
            PHASE5C2_CLOSEOUT,
            PHASE5C3_CLOSEOUT,
            PHASE5C4_CLOSEOUT,
            PHASE5C5_CLOSEOUT,
            PHASE5D0_CLOSEOUT,
            PHASE5D1_CLOSEOUT,
            PHASE5D2_CLOSEOUT,
            PHASE5D3_CLOSEOUT,
            PHASE5D4_CLOSEOUT,
            PHASE5D5_CLOSEOUT,
            PHASE5D6_CLOSEOUT,
            PHASE5E2A1_CLOSEOUT,
            PHASE5E2A2_CLOSEOUT,
            PHASE5E2A21_CLOSEOUT,
        ],
        "closeout": PHASE5E2B11_CLOSEOUT,
        "baseline_release": {
            "tag": "v0.4.0-alpha.1",
            "commit": "30d6e77780175deeffc5c211749bcb0169aa1dde",
        },
        "authorized_next": [
            "Phase 5E-2B.1-2A acceptance closeout"
        ],
        "prohibited": [
            "Phase 5E-2B.1-2B",
            "Phase 5E-2B.1-2C",
            "Phase 5E-2B.1-3",
            "Phase 5E-2C",
            "Phase 5E-2D",
            "Phase 5E-2E",
            "Phase 5E-2F",
            "Phase 5E-3",
            "Phase 5E-4",
            "Phase 5E-5",
            "Phase 5E-6",
            "Phase 5F",
            "Phase 6",
            "Phase 7",
            "Phase 8",
            "Phase 9",
        ],
        "release_tag": None,
    }
    accepted_prohibited = [
        item for item in expected["prohibited"] if item != "Phase 5E-2B.1-2B"
    ]
    if stage in {"2a_accepted", "2b_pending", "2b_accepted", "s3"}:
        expected.update(
            {
                "current_phase": "Phase 5E-2B.1-2A",
                "status": "accepted_closed",
                "authorized_next": [
                    "Phase 5E-2B.1-2B canonical-event roll-forward implementation"
                ],
                "prohibited": accepted_prohibited,
            }
        )
    if stage == "2b_pending":
        expected.update(
            {
                "current_phase": "Phase 5E-2B.1-2B",
                "status": "implementation_complete_pending_acceptance",
                "authorized_next": ["Phase 5E-2B.1-2B acceptance closeout"],
            }
        )
    elif stage in {"2b_accepted", "s3"}:
        expected.update(
            {
                "current_phase": "Phase 5E-2B.1-2B",
                "status": "accepted_closed",
                "authorized_next": ["Phase 5E-2B.1-2C successor-gate bootstrap"],
            }
        )
    elif stage in {"g1", "g2", "g3", "g4", "g5"}:
        if successor_position is None:
            raise SystemExit("recursive successor state lacks its protected position")
        authority = successor_position.get("authority")
        bundle = successor_position.get("bundle")
        if not isinstance(authority, dict):
            raise SystemExit("recursive successor authority has an open shape")
        patch_by_stage = {
            "g1": authority["pending_gate_state"],
            "g2": authority["accepted_gate_state"],
            "g3": authority["successor_pending_state"],
            "g4": authority["successor_accepted_state"],
        }
        if stage == "g5":
            if not isinstance(bundle, dict) or not isinstance(
                bundle.get("post_successor_closeout"), dict
            ):
                raise SystemExit("terminal recursive successor state lacks its closeout policy")
            expected.update(bundle["post_successor_closeout"]["accepted_state"])
        else:
            expected.update(patch_by_stage[stage])
    return expected


def main() -> int:
    state = json.loads((ROOT / "docs" / "phase-status.json").read_text(encoding="utf-8"))
    acceptance_closeout = ROOT / "docs/phase5e2b12a-acceptance-closeout.json"
    implementation_test = ROOT / "tests/test_phase5e2b12b_canonical_event_consumption.py"
    implementation_closeout = ROOT / "docs/phase5e2b12b-acceptance-closeout.json"
    markers = (
        acceptance_closeout.is_file(),
        implementation_test.is_file(),
        implementation_closeout.is_file(),
    )
    stage_by_markers = {
        (False, False, False): "2a_pending",
        (True, False, False): "2a_accepted",
        (True, True, False): "2b_pending",
        (True, True, True): "2b_accepted",
    }
    stage = stage_by_markers.get(markers)
    if stage is None:
        raise SystemExit("Phase 5E-2B.1 state markers form an impossible combination")
    successor_position: dict[str, object] | None = None
    if stage == "2b_accepted":
        successor_position = _resolve_successor_position("HEAD")
        stage_value = successor_position.get("stage")
        if stage_value not in {"s3", "g1", "g2", "g3", "g4", "g5"}:
            raise SystemExit("generic Phase 5E successor markers form an invalid state")
        stage = str(stage_value)
    expected = _expected_phase_state(stage=stage, successor_position=successor_position)
    if state != expected:
        raise SystemExit("phase-status.json does not match Phase 5E-2B.1-2A boundary")
    if stage != "2a_pending":
        _verify_phase5e2b12a_acceptance_topology(acceptance_closeout)
    recorded_closeouts = (
        *state["prior_closeouts"],
        state["closeout"]["policy_closeout"]["historical_phase5e2b_closeout"],
        state["closeout"]["implementation"],
    )
    public_snapshot_required = any(
        not (
            commit_exists(str(closeout["substantive_head_commit"]), ROOT)
            and commit_exists(str(closeout["substantive_merge_commit"]), ROOT)
        )
        for closeout in recorded_closeouts
    )
    if public_snapshot_required:
        verify_public_bootstrap_snapshot(ROOT)
    for closeout in recorded_closeouts:
        _verify_recorded_closeout_tree(
            closeout,
            public_snapshot_verified=public_snapshot_required,
        )
    files = {
        "AGENTS.md": ROOT / "AGENTS.md",
        "README.md": ROOT / "README.md",
        "roadmap": ROOT / "docs" / "roadmap.md",
        "main Skill": (
            ROOT / "plugins/owner-equity-research/skills/owner-equity-research/SKILL.md"
        ),
        "audit Skill": (
            ROOT / "plugins/owner-equity-research/skills/owner-research-audit/SKILL.md"
        ),
    }
    required = (
        "Phase 5B",
        "Phase 5C-0",
        "Phase 5C-1",
        "Phase 5C-2",
        "Phase 5C-3",
        "Phase 5C-4",
        "Phase 5C-5",
        "Phase 5D-0",
        "Phase 5D-1",
        "Phase 5D-2",
        "Phase 5D-3",
        "Phase 5D-4",
        "Phase 5D-5",
        "Phase 5D-6",
        "Phase 5E-0",
        "Phase 5E-1",
        "Phase 5E-1.1",
        "v0.4.0-alpha.1",
        "accepted/closed",
        "2.1.3",
        "2.1.4",
        "2.1.5",
        "2.1.5.1",
        "2.2.0",
        "2.2.1",
        "2.2.2",
        "2.2.3",
        "2.2.4",
        "2.2.5",
        "2.2.6",
        "2.3.0",
        "2.3.1",
        "2.3.1.1",
        "2.3.2",
        "2.3.2.1",
        "2.3.2.2",
        "2.3.2.2.1",
        "2.3.2.3",
        "2.3.2.3.1",
        "2.3.2.3.2",
        "2.3.2.3.3",
        "Phase 5E-2B.1",
        "Phase 5E-2F",
    )
    for label, path in files.items():
        text = path.read_text(encoding="utf-8")
        missing = [token for token in required if token not in text]
        if missing:
            raise SystemExit(f"{label} phase state is stale: missing={missing}")
    recursive_state_files = {
        **files,
        "completion overlay v2": ROOT / "docs/phase5-completion-overlay-v2.md",
        "integration contract": ROOT / "docs/phase5e2b12a-integration-contracts.md",
        "market policy reference": (
            ROOT
            / "plugins/owner-equity-research/skills/owner-equity-research/references/"
            "market-execution-policy.md"
        ),
    }
    canonical_recursive_authority = (
        "Phase 5 current authority: S3 -> G1 -> G2 -> G3 -> G4 -> G5 -> external "
        "2C-P; after feasibility a new protected gate is required; Phase 6-9 require "
        "separate reviewed control-plane authorization; Phase 5E-2B.1-2C != Phase "
        "5E-2C."
    )
    for label, path in recursive_state_files.items():
        normalized = re.sub(r"\s+", " ", path.read_text(encoding="utf-8"))
        if canonical_recursive_authority not in normalized:
            raise SystemExit(
                f"{label} omits the canonical current successor-gate authority statement"
            )
    agents = files["AGENTS.md"].read_text(encoding="utf-8")
    for prohibited in ("Phase 5E-3", "Phase 5F", "Phase 9"):
        if prohibited not in agents:
            raise SystemExit(f"AGENTS.md omits prohibited boundary: {prohibited}")
    if "Phase 5E-2B.1" not in agents or "Phase 5E-2C" not in agents:
        raise SystemExit("AGENTS.md omits the corrective successor boundary")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
