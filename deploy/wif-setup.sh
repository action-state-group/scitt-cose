#!/usr/bin/env bash
# One-time Google Cloud setup for .github/workflows/deploy.yml, run by a
# project owner of fluxxom (it changes IAM policy; Editor is not enough). It:
#   - enables the APIs workload identity federation needs;
#   - creates a workload identity pool `github` (if absent) and an OIDC
#     provider `scitt-verifier` that accepts only GitHub's tokens for this
#     repository (matched by its numeric id, which survives a rename), for the
#     `production` environment and `main`'s copy of deploy.yml. The environment
#     requires Steven's approval, so Google trusts a run only after his click.
#     A provider that already exists is updated to exactly that;
#   - creates a service account `scitt-verifier-deploy` with the roles a source
#     deploy to Cloud Run needs, and nothing else;
#   - lets that provider's tokens act as the service account.
# No service account key is created. Re-running it is safe: what exists is
# kept or brought back to these settings, and any other error stops it.
#
#   deploy/wif-setup.sh            print the commands
#   deploy/wif-setup.sh --apply    run them
set -euo pipefail

PROJECT=fluxxom
REGION=us-central1
SERVICE=scitt-verifier
REPO=action-state-group/scitt-cose
REPO_ID=1266637291 # gh api repos/action-state-group/scitt-cose --jq .id
POOL=github
PROVIDER=scitt-verifier
SA_NAME=scitt-verifier-deploy
SA="$SA_NAME@$PROJECT.iam.gserviceaccount.com"
MAPPING='google.subject=assertion.sub,attribute.repository_id=assertion.repository_id,attribute.environment=assertion.environment,attribute.workflow_ref=assertion.workflow_ref'
CONDITION="assertion.repository_id == '$REPO_ID' && assertion.environment == 'production' && assertion.workflow_ref == '$REPO/.github/workflows/deploy.yml@refs/heads/main'"

apply=0
case "${1:-}" in
  "") ;;
  --apply) apply=1 ;;
  *) echo "usage: $0 [--apply]" >&2; exit 2 ;;
esac

# run prints a command so it can be pasted into a shell, or runs it.
run() {
  if [ "$apply" = 1 ]; then
    "$@"
  else
    printf '%q ' "$@"
    echo
  fi
}

# state prints the state of what a describe command finds (ACTIVE, or DELETED
# for a pool or provider deleted in the last 30 days), or nothing when there
# is none. It reads what is there now, in either mode.
state() {
  "$@" --format='value(state)' 2>/dev/null || true
}

number="$(gcloud projects describe "$PROJECT" --format='value(projectNumber)')"
runtime_sa="$(gcloud run services describe "$SERVICE" --project "$PROJECT" --region "$REGION" \
  --format='value(spec.template.spec.serviceAccountName)')"
# A source deploy builds as Cloud Build's default identity, the Compute
# Engine default service account, and runs as the service's runtime identity
# (the same account unless the service names another).
build_sa="$number-compute@developer.gserviceaccount.com"
runtime_sa="${runtime_sa:-$build_sa}"

run gcloud services enable iam.googleapis.com iamcredentials.googleapis.com sts.googleapis.com \
  cloudresourcemanager.googleapis.com --project "$PROJECT"

case "$(state gcloud iam workload-identity-pools describe "$POOL" --project "$PROJECT" --location global)" in
  "") run gcloud iam workload-identity-pools create "$POOL" --project "$PROJECT" --location global \
    --display-name "GitHub Actions" ;;
  DELETED) run gcloud iam workload-identity-pools undelete "$POOL" --project "$PROJECT" --location global ;;
esac
provider_args=(--project "$PROJECT" --location global --workload-identity-pool "$POOL"
  --issuer-uri https://token.actions.githubusercontent.com
  --attribute-mapping "$MAPPING" --attribute-condition "$CONDITION")
case "$(state gcloud iam workload-identity-pools providers describe "$PROVIDER" --project "$PROJECT" \
  --location global --workload-identity-pool "$POOL")" in
  "") run gcloud iam workload-identity-pools providers create-oidc "$PROVIDER" "${provider_args[@]}" ;;
  DELETED)
    run gcloud iam workload-identity-pools providers undelete "$PROVIDER" --project "$PROJECT" \
      --location global --workload-identity-pool "$POOL"
    run gcloud iam workload-identity-pools providers update-oidc "$PROVIDER" "${provider_args[@]}" ;;
  *) run gcloud iam workload-identity-pools providers update-oidc "$PROVIDER" "${provider_args[@]}" ;;
esac
if [ -z "$(gcloud iam service-accounts describe "$SA" --project "$PROJECT" --format='value(email)' 2>/dev/null || true)" ]; then
  run gcloud iam service-accounts create "$SA_NAME" --project "$PROJECT" \
    --display-name "Deploys $REPO to Cloud Run $SERVICE"
  # A new account can take a few seconds to become visible to IAM.
  if [ "$apply" = 1 ]; then
    for _ in 1 2 3 4 5 6 7 8 9 10; do
      gcloud iam service-accounts describe "$SA" --project "$PROJECT" >/dev/null 2>&1 && break
      sleep 3
    done
  fi
fi

# What a source deploy needs: Cloud Build, the source bucket and Artifact
# Registry (run.sourceDeveloper), quota checks (serviceUsageConsumer), and
# acting as the build and runtime identities (serviceAccountUser on each).
for role in roles/run.sourceDeveloper roles/serviceusage.serviceUsageConsumer; do
  run gcloud projects add-iam-policy-binding "$PROJECT" --member "serviceAccount:$SA" --role "$role" \
    --condition None --quiet
done
for account in $(printf '%s\n' "$build_sa" "$runtime_sa" | sort -u); do
  run gcloud iam service-accounts add-iam-policy-binding "$account" --project "$PROJECT" \
    --member "serviceAccount:$SA" --role roles/iam.serviceAccountUser
done
run gcloud iam service-accounts add-iam-policy-binding "$SA" --project "$PROJECT" \
  --role roles/iam.workloadIdentityUser \
  --member "principalSet://iam.googleapis.com/projects/$number/locations/global/workloadIdentityPools/$POOL/attribute.repository_id/$REPO_ID"

cat <<VARS

Then set these repository variables (not secrets; neither is a credential):
  gh variable set GCP_WORKLOAD_IDENTITY_PROVIDER --repo $REPO --body projects/$number/locations/global/workloadIdentityPools/$POOL/providers/$PROVIDER
  gh variable set GCP_DEPLOY_SERVICE_ACCOUNT --repo $REPO --body $SA
VARS
