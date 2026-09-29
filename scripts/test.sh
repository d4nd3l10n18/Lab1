#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
project_dir="$(cd -- "$script_dir/.." && pwd)"

docker compose --env-file "$project_dir/infra/.env.example" \
  -f "$project_dir/infra/compose.yaml" up -d --wait
dotnet build "$project_dir/src/SecureLab.Api/SecureLab.Api.csproj" --configuration Release
# Тести використовують ту саму локальну БД, тому спершу повертаємо відомий seed-стан.
dotnet run --no-build --configuration Release \
  --project "$project_dir/src/SecureLab.Api" -- --reset-database
dotnet test "$project_dir/tests/SecureLab.Api.Tests/SecureLab.Api.Tests.csproj" \
  --configuration Release