#!/bin/sh
set -eu

jq empty config/services.example.json
jq empty config/policy.example.json
jq empty tests/sample-subscription.json
jq empty tests/sample-subscription-array.json
jq empty tests/sample-health.json
jq empty config/routes.example.json
jq empty tests/routes/direct.json
jq empty tests/routes/vless-frankfurt.json
jq empty tests/sample-route-plan.json

sh scripts/validate-subscription.sh tests/sample-subscription.json >/tmp/router-policy-validate.out
sh scripts/validate-subscription.sh tests/sample-subscription-array.json >/tmp/router-policy-validate-array.out
sh scripts/summarize-subscription.sh tests/sample-subscription-array.json >/tmp/router-policy-subscription-summary.json
sh scripts/summarize-subscription.sh tests/sample-subscription.json >/tmp/router-policy-subscription-summary-object.json
sh scripts/build-candidates.sh chatgpt.com openai false >/tmp/router-policy-candidates.json
jq empty /tmp/router-policy-candidates.json
sh scripts/dry-run-routing.sh config/services.example.json tests/sample-health.json >/tmp/router-policy-plan.json
jq empty /tmp/router-policy-plan.json
sh scripts/apply-route-plan.sh tests/sample-route-plan.json >/tmp/router-policy-apply.out

echo "local_checks_ok=true"
