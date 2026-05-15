# Atlas Cloud Provider Review

## What Changed

- Added a first-class `atlas` AI provider preset in `autofix`.
- Defaulted Atlas Cloud traffic to `https://api.atlascloud.ai/v1`.
- Added Atlas model aliases:
  - `atlas` -> `deepseek-ai/deepseek-v4-flash`
  - `atlas-deepseek-v4-flash` -> `deepseek-ai/deepseek-v4-flash`
  - `atlas-qwen3-coder-next` -> `qwen/qwen3-coder-next`
  - `atlas-kimi-k2.6` -> `moonshotai/kimi-k2.6`
  - `atlas/<model-id>` and `atlas:<model-id>` for direct model pass-through
- Added `ATLASCLOUD_API_KEY` fallback support in the CLI when `-ai-api-provider` starts with `atlas`.
- Updated README with Atlas Cloud usage, examples, and the official link:
  `https://www.atlascloud.ai/?utm_source=github&utm_medium=link&utm_campaign=gosec`
- Added `.env.example` for local setup and ignored `.env.local` files.

## Files Changed

- `autofix/ai.go`
- `autofix/atlas.go`
- `autofix/ai_test.go`
- `autofix/atlas_test.go`
- `cmd/gosec/main.go`
- `README.md`
- `.gitignore`
- `.env.example`

## Local Validation Plan

- Unit test the `autofix` package.
- Build and run `gosec` against a temporary vulnerable sample with `-ai-api-provider=atlas`.
- Validate direct Atlas Cloud non-stream and stream responses with the provided API key.

## Validation Results

- `go test ./...` passed.
- Atlas Cloud `/v1/models` responded successfully and returned account-accessible model IDs.
- Atlas Cloud non-stream chat completion succeeded with `deepseek-ai/deepseek-v4-flash`.
- Atlas Cloud stream chat completion succeeded with `deepseek-ai/deepseek-v4-flash`.
- `gosec` binary integration succeeded:
  `-ai-api-provider=atlas` generated a live Autofix for a temporary `G402` sample.
