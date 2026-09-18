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
    condition:
        any of ($override_*) or any of ($verdict_*) or any of ($role_*)
}
