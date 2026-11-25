#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
workflow="$root/.github/workflows/release-candidate.yml"

fail() {
  printf '%s\n' "$*" >&2
  exit 1
}

[[ -f "$workflow" ]] || fail "missing release candidate workflow: $workflow"
[[ ! -e "$root/.github/workflows/m7-pretag-approval.yml" ]] || fail "legacy M7 pre-tag workflow still exists"
[[ ! -e "$root/scripts/require-m7-approval.sh" ]] || fail "legacy M7 approval helper still exists"

for candidate in "$root"/.github/workflows/*.yml; do
  if grep -Eiq 'm7|external security review' "$candidate"; then
    fail "workflow still references an M7/external security review gate: $candidate"
  fi
done

if grep -Eq '^    environment:' "$workflow"; then
  fail "release candidate workflow must not require a protected review environment"
fi

job_body() {
  local job=$1
  awk -v target="  $job:" '
    $0 == target { in_job = 1 }
    in_job && /^  [[:alnum:]_-]+:$/ && $0 != target { exit }
    in_job { print }
  ' "$workflow"
}

for job in validate quality create_tag dispatch_release; do
  [[ "$(grep -Ec "^  ${job}:$" "$workflow")" -eq 1 ]] || fail "expected exactly one ${job} job"
done

validate_job=$(job_body validate)
quality_job=$(job_body quality)
create_tag_job=$(job_body create_tag)
dispatch_job=$(job_body dispatch_release)

grep -Fq '          ref: ${{ github.sha }}' <<<"$validate_job" || fail "candidate validation must check out the dispatched SHA"
grep -Fq '          persist-credentials: false' <<<"$validate_job" || fail "candidate validation must not persist checkout credentials"
grep -Fq '          scripts/test-release-notes.sh' <<<"$validate_job" || fail "candidate validation must run release-note controls"
grep -Fq '          scripts/test-release-candidate.sh' <<<"$validate_job" || fail "candidate validation must run pre-tag controls"
grep -Fq '          scripts/test-release-workflow.sh' <<<"$validate_job" || fail "candidate validation must run workflow controls"
grep -Fq '          scripts/validate-release-candidate.sh "$VERSION"' <<<"$validate_job" || fail "candidate validation must run the version guard"
! grep -Fq '    if:' <<<"$validate_job" || fail "candidate validation must not be optional"

grep -Fq '    needs: validate' <<<"$quality_job" || fail "full CI must run after candidate validation"
grep -Fq '    uses: ./.github/workflows/ci.yml' <<<"$quality_job" || fail "release must run the full reusable CI workflow"
! grep -Fq '    if:' <<<"$quality_job" || fail "full CI must not be optional"

grep -Fq '    needs: [validate, quality]' <<<"$create_tag_job" || fail "tag creation must require candidate validation and full CI"
grep -Fq '      contents: write' <<<"$create_tag_job" || fail "tag creation needs contents: write"
grep -Fq '[[ "$GITHUB_REF" == "refs/heads/main" ]]' <<<"$create_tag_job" || fail "tag creation must run from main"
grep -Fq '[[ "$GITHUB_WORKFLOW_SHA" == "$GITHUB_SHA" ]]' <<<"$create_tag_job" || fail "tag creation must bind the workflow SHA to the candidate SHA"
grep -Fq '[[ "$VERSION" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]' <<<"$create_tag_job" || fail "tag creation must validate stable SemVer"
grep -Fq 'ref=refs/tags/$tag' <<<"$create_tag_job" || fail "tag creation must create a version tag ref"
grep -Fq 'object=$GITHUB_SHA' <<<"$create_tag_job" || fail "tag object must target the candidate SHA"
grep -Fq 'sha=$tag_object' <<<"$create_tag_job" || fail "tag ref must target the annotated tag object"
grep -Fq 'GH_TOKEN: ${{ github.token }}' <<<"$create_tag_job" || fail "tag creation must scope its token to the inline step"
! grep -Fq 'actions/checkout' <<<"$create_tag_job" || fail "tag creation must not check out candidate code"
! grep -Fq 'scripts/' <<<"$create_tag_job" || fail "tag creation must not execute candidate scripts"
! grep -Fq '    if:' <<<"$create_tag_job" || fail "tag creation must not be optional"
if grep -Eq -- '--force|--force-with-lease' <<<"$create_tag_job"; then
  fail "release tag workflow must never force-update refs"
fi
[[ "$(grep -Fc 'contents: write' "$workflow")" -eq 1 ]] || fail "contents: write must appear only in the tag job"

grep -Fq '    needs: create_tag' <<<"$dispatch_job" || fail "release dispatch must wait for tag creation"
grep -Fq "if: github.repository == 'gyrel/sandboxes-daemon' || github.repository == 'gyrel/sandboxes-cli'" <<<"$dispatch_job" || fail "release dispatch must stay limited to release-asset repositories"
grep -Fq 'TAG: v${{ inputs.version }}' <<<"$dispatch_job" || fail "release dispatch must use the created tag"
grep -Fq 'ref=$TAG' <<<"$dispatch_job" || fail "release dispatch must target the created tag"
! grep -Fq 'contents: write' <<<"$dispatch_job" || fail "release dispatch must not receive contents: write"
grep -Fq '      actions: write' <<<"$dispatch_job" || fail "release dispatch needs actions: write"
grep -Fq 'actions/workflows/release.yml/dispatches' <<<"$dispatch_job" || fail "release dispatch must start the tag-triggered release workflow"
[[ "$(grep -Fc 'actions: write' "$workflow")" -eq 1 ]] || fail "actions: write must appear only in the dispatch job"

if [[ -f "$root/.github/workflows/release.yml" ]]; then
  grep -Fq '  workflow_dispatch:' "$root/.github/workflows/release.yml" || fail "release workflow must accept dispatch"
fi

printf 'PASS: no M7/external security review gate; candidate validation and full CI remain required\n'
printf 'PASS: tag write token is isolated; immutable non-force tag and release dispatch boundaries hold\n'
