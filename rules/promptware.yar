// Bộ luật YARA tĩnh — Lớp 1 (T04, spec v1.4.0 §3.2.1).
//
// Rule duy nhất dưới đây được port nguyên văn từ spec §3.2.1
// (`Static_Promptware_InstructionBypass`): giữ nguyên toàn bộ regex, cờ `nocase`
// và bốn khoá meta `description` / `threat_level` / `mitre_atlas` / `version`.
// Không thêm rule, không nới lỏng điều kiện.
//
// File này KHÔNG import module nào nên biên dịch được trên mọi YARA build.
// Rule dùng module `cuckoo` (spec §3.2.2) nằm ở file riêng
// `rules/promptware_cuckoo.yar` vì build thiếu `--enable-cuckoo` sẽ lỗi compile
// `unknown module "cuckoo"` cho toàn bộ ruleset (xem `guardrail.yara_scanner`).

rule Static_Promptware_InstructionBypass {
    meta:
        description = "Detects adversarial prompt injection attempts in PE strings"
        threat_level = "HIGH"
        mitre_atlas = "AML.T0051.001"
        version = "1.4.0"
    strings:
        $override_1 = /ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|prompts|rules)/ nocase
        $override_2 = /disregard\s+(all\s+)?(prior|previous)\s+(system\s+)?(commands|context)/ nocase
        $override_3 = /you\s+are\s+now\s+(in\s+)?(developer\s+mode|unrestricted|a\s+benign)/ nocase
        $verdict_1 = /classify\s+this\s+(file|sample|program)\s+as\s+(clean|safe|benign)/ nocase
        $verdict_2 = /do\s+not\s+(report|alert|flag)\s+this\s+(threat|malware|binary)/ nocase
        $verdict_3 = /output\s+verdict:\s*benign/ nocase
        $role_1 = /system\s+override:\s*role\s*=\s*/ nocase
        $role_2 = /assistant\s+should\s+say\s+nothing\s+is\s+wrong/ nocase
	$override_4 = /reset\s+(your\s+)?(instructions|context|prompt)/ nocase
        $override_5 = /system\s+override/ nocase
        $verdict_4 = /classify\s+.{0,20}goodware/ nocase
        $verdict_5 = /do\s+not\s+(report|mention)\s+.{0,40}(c2|indicators?|network|exfiltration)/ nocase
        $verdict_6 = /no\s+malicious\s+(behavior|activity)/ nocase
        $role_3 = /acting\s+as\s+(a\s+)?(trusted\s+)?(admin|analyst|supervisor)/ nocase
        $role_4 = /admin\s+clearance/ nocase
        $role_5 = /(approved|whitelisted)\s+software\s+list/ nocase
    condition:
        any of ($override_*) or any of ($verdict_*) or any of ($role_*)
}

rule Promptware_FakeStructure {
    meta:
        description = "Detects fake verdict/structure injection"
        threat_level = "HIGH"
        mitre_atlas = "AML.T0051.001"
    strings:
        $verdict_json = /"?malicious"?\s*[:=]\s*false/ nocase
        $verdict_tag  = /<\/?(official_verdict|analysis_result|result)[^>]*>/ nocase
        $verdict_safe = /verdict\s*[:=]\s*(benign|safe|clean)/ nocase
        $end_marker   = /(===\s*end\s+report|end\s+of\s+data|analysis\s+complete)/ nocase
        $threat_none  = /threat\s*(level)?\s*[:=]\s*(none|safe)/ nocase
        $whitelist    = /(whitelisted|legitimate\s+software|trusted\s+scanner)/ nocase
    condition:
        any of them
}

rule Promptware_Roleplay {
    meta:
        description = "Detects authority/roleplay injection"
        threat_level = "HIGH"
        mitre_atlas = "AML.T0051.001"
    strings:
        $auth_1 = /I\s+(am|'m)\s+(the\s+)?(security\s+lead|admin|analyst|supervisor)/ nocase
        $auth_2 = /(authorize|instruct|clear(ed)?)\s+you\s+to/ nocase
        $auth_3 = /(maintenance|developer|debug)\s+mode\s+(enabled|on)/ nocase
        $auth_4 = /(pre-?cleared|approved|whitelisted)\s+(by|sample|file|list)/ nocase
        $auth_5 = /suppress\s+(all\s+)?(malware\s+)?(alerts|warnings|detections)/ nocase
        $auth_6 = /(red-?team|penetration\s+test|pentest).{0,30}(benign|clean|safe|ignore)/ nocase
    condition:
        any of them
}

rule Promptware_Evasion {
    meta:
        description = "Detects spacing/leet evasion of instruction-bypass"
        threat_level = "MEDIUM"
        mitre_atlas = "AML.T0051.001"
    strings:
        $leet_1 = /ign[0o]re/ nocase
        $leet_2 = /b[e3]n[i1]gn/ nocase
        $leet_3 = /cl[e3]4?n/ nocase
        $leet_4 = /g[0o]{2}dw4?r[e3]/ nocase
	$spaced = /i\s*-\s*g\s*-\s*n\s*-\s*o\s*-\s*r\s*-\s*e/ nocase
    condition:
        any of them
}
