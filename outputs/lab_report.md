# Lab 11 — Auto Report

> File này **tự sinh** bởi `scripts/grade.py`. **Không** viết / sửa tay.

- Generated (UTC): `2026-09-26T07:31:50.104781+00:00`
- Framework: `—`
- Technical failure: **True**

## Packaging

| File | Status |
|------|--------|
| results.json | MISSING |
| attack_results.json | MISSING |
| audit_log.json | OK |
| metrics.json | OK |

## Schema (`results.json`)

- Valid: **False**
- Error: `missing outputs/results.json`

## Defense snapshot (từ `results.json`)

- Safe queries blocked: `None/None`
- Attack queries blocked: `None/None`
- Edge cases blocked: `None/None`
- Rate limit blocked/sent: `None/None`

## Red Team snapshot (từ `attack_results.json`)

- Provider / model: `None` / `None`
- Unsafe leaks (Red): `None/None`
- Guards leaks (Red Advance): `None/None`

## Public tests

- Return code: `0`
- Technical failure: `False`

```text
.............ssss                                                        [100%]
13 passed, 4 skipped in 1.22s
```

## Notes

- Artifact chấm chính: `outputs/results.json` + `outputs/attack_results.json`.
- Bonus B1/B2 do grader replay quyết định — JSON chỉ là bằng chứng.
- Không nộp `report/*.md` viết tay; dùng file này nếu cần xem tóm tắt.
