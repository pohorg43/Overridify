import os
import re

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sh_path = None
cur_dir = BASE_DIR
for _ in range(4):
    cand = os.path.join(cur_dir, 'common', 'database', 'aosp_reference.sh')
    if os.path.exists(cand):
        sh_path = cand
        break
    cur_dir = os.path.dirname(cur_dir)
if not sh_path:
    sh_path = os.path.abspath('common/database/aosp_reference.sh')

awk_script_path = os.path.join(os.path.dirname(sh_path), 'aosp_reference.awk')

with open(sh_path, 'r', encoding='utf-8') as f:
    lines = f.readlines()

exact_rules = {}
dyn_rules = []       # (is_regex, pattern_or_regex, api_thresh, val_ge, val_lt)
wildcard_rules = []  # (regex, meta_val, glob)

current_prefix = ""
in_sub_case = False


def glob_to_regex(glob):
    r = glob.replace('.', r'\.')
    r = r.replace('*', '.*')
    return '^' + r + '$'


def normalize_meta(meta):
    if not meta or meta == ":::":
        return ":::"
    if meta.startswith(':'):
        return 'none' + meta
    return meta


def extract_case_pattern(idx):
    line_s = lines[idx].strip()
    pat_part = None
    back_start = idx - 1

    # Игнорируем объявления shell-функций вида func_name() {
    if re.match(r'^[a-zA-Z0-9_]+\s*\(\)\s*\{', line_s):
        return None

    # Отрезаем тело команды после закрывающей скобки паттерна case
    code_before_ret = re.split(r'\bRET_META=|\[\s*"\$api"', line_s)[0]
    if ')' in code_before_ret:
        pat_part = code_before_ret.split(')')[0].strip()
    else:
        for back in range(idx - 1, max(-1, idx - 15), -1):
            prev = lines[back].strip()
            if not prev or prev.startswith('#'):
                continue
            if re.match(r'^[a-zA-Z0-9_]+\s*\(\)\s*\{', prev) or prev.startswith('case ') or prev.endswith(';;'):
                break
            if ')' in prev:
                pat_part = prev.split(')')[0].strip()
                back_start = back - 1
                break

    if not pat_part:
        return None

    parts = [pat_part]
    for back in range(back_start, -1, -1):
        prev = lines[back].strip()
        if prev.endswith('\\'):
            prev_clean = prev[:-1].strip()
            if prev_clean.endswith('|'):
                parts.insert(0, prev_clean)
            else:
                break
        elif prev.endswith('|'):
            parts.insert(0, prev)
        else:
            break
    return "".join(parts)


for i, line in enumerate(lines):
    line_s = line.strip()
    if not line_s or line_s.startswith('#'):
        continue

    m_sub = re.match(r'sub="\$\{prop#([^}]+)\}"', line_s)
    if m_sub:
        current_prefix = m_sub.group(1)
        in_sub_case = True
        continue

    if in_sub_case and line_s.startswith('esac'):
        current_prefix = ""
        in_sub_case = False
        continue

    if 'RET_META=' not in line_s:
        continue

    # 1. Динамические правила, зависящие от $api
    m_cond = re.search(
        r'\[\s*"\$api"\s*-ge\s*(\d+)\s*\]\s*&&\s*RET_META="([^"]+)"\s*\|\|\s*RET_META="([^"]+)"',
        line_s
    )
    if m_cond:
        api_thresh = int(m_cond.group(1))
        val_ge = normalize_meta(m_cond.group(2))
        val_lt = normalize_meta(m_cond.group(3))
        pat = extract_case_pattern(i)
        if not pat or pat == '*':
            continue
        for sp in [p.strip() for p in pat.split('|') if p.strip()]:
            full_p = (current_prefix + sp) if in_sub_case else sp
            if '*' in full_p:
                dyn_rules.append((True, glob_to_regex(full_p), api_thresh, val_ge, val_lt))
            else:
                dyn_rules.append((False, full_p, api_thresh, val_ge, val_lt))
        continue

    # 2. Статические правила (точные и с маской *)
    m_meta = re.search(r'RET_META="([^"]+)"', line_s)
    if m_meta:
        meta_val = normalize_meta(m_meta.group(1))
        if meta_val == ":::":
            continue
        pat = extract_case_pattern(i)
        if not pat or pat == '*':
            continue
        for sp in [p.strip() for p in pat.split('|') if p.strip()]:
            full_p = (current_prefix + sp) if in_sub_case else sp
            if '*' in full_p:
                wildcard_rules.append((glob_to_regex(full_p), meta_val, full_p))
            else:
                if full_p not in exact_rules:
                    exact_rules[full_p] = meta_val

# Генерация AWK-скрипта
awk_lines = [
    '# Generated AWK resolver for aosp_reference',
    'function resolve_meta(p, api) {',
    '    if (p in exact) return exact[p];'
]

for is_regex, pat, thresh, val_ge, val_lt in dyn_rules:
    if is_regex:
        awk_lines.append(f'    if (p ~ /{pat}/) return (api >= {thresh} ? "{val_ge}" : "{val_lt}");')
    else:
        awk_lines.append(f'    if (p == "{pat}") return (api >= {thresh} ? "{val_ge}" : "{val_lt}");')

for reg, meta, _ in wildcard_rules:
    awk_lines.append(f'    if (p ~ /{reg}/) return "{meta}";')

awk_lines.extend([
    '    return ":::";',
    '}',
    'BEGIN {'
])

for p, m in sorted(exact_rules.items()):
    awk_lines.append(f'    exact["{p}"] = "{m}";')

awk_lines.extend([
    '}',
    '{',
    '    if ($0 != "") {',
    '        m = resolve_meta($0, api);',
    '        print $0 ":" m;',
    '        seen[$0] = 1;',
    '    }',
    '}',
    'END {',
    '    if (single_mode) exit;',
    '    if (lc_f != "") {',
    '        while ((getline l < lc_f) > 0) {',
    '            c = index(l, ":");',
    '            if (c > 1) seen[substr(l, 1, c - 1)] = 1;',
    '        }',
    '        close(lc_f);',
    '    }',
    '    for (p in exact) {',
    '        if (!seen[p]) {',
    '            m = resolve_meta(p, api);',
    '            print p ":" m;',
    '        }',
    '    }',
    '}'
])

with open(awk_script_path, 'w', encoding='utf-8') as f:
    f.write('\n'.join(awk_lines) + '\n')

print(f"Generated {awk_script_path} with {len(exact_rules)} exact, {len(dyn_rules)} dynamic, {len(wildcard_rules)} wildcards.")