from pathlib import Path

WORKFLOW = (Path(__file__).parents[1] / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")


def test_release_recovery_is_explicitly_dispatchable_against_exact_existing_tag_sha() -> None:
    assert "workflow_dispatch:" in WORKFLOW
    assert "tag:" in WORKFLOW
    assert "expected_sha:" in WORKFLOW
    assert "RELEASE_TAG:" in WORKFLOW
    assert "EXPECTED_SHA:" in WORKFLOW
    assert 'test "$(git rev-parse HEAD)" = "${EXPECTED_SHA}"' in WORKFLOW


def test_release_build_outputs_are_outside_repository_checkout() -> None:
    assert 'release_work_dir="$(mktemp -d)"' in WORKFLOW
    assert 'uv build --out-dir "$release_work_dir/dist-a"' in WORKFLOW
    assert 'uv build --out-dir "$release_work_dir/dist-b"' in WORKFLOW
    assert 'cmp "$artifact" "$release_work_dir/dist-b/$(basename "$artifact")"' in WORKFLOW
    assert "uv build --out-dir dist-a" not in WORKFLOW
    assert "uv build --out-dir dist-b" not in WORKFLOW


def test_release_assets_still_publish_from_exact_verified_build() -> None:
    assert 'cp "$release_work_dir/dist-a/"* dist/' in WORKFLOW
    assert "sha256sum dist/*.whl dist/*.tar.gz" in WORKFLOW
    assert 'gh release create "${RELEASE_TAG}"' in WORKFLOW
    assert 'gh release upload "${RELEASE_TAG}"' in WORKFLOW
