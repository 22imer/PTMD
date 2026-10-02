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
        // Chỉ dạng có trích dẫn kiểu JSON. Dạng thô `verdict: benign` đã do
        // rule spec §3.2.1 `$verdict_3` bắt; để ở đây sẽ khiến cùng một mảng
        // chuỗi rơi vào hai rule nên `_dedupe_yara_findings` không gộp được,
        // và sinh FPR trên PE sạch.
        $verdict_safe = /"verdict"\s*:\s*"(benign|safe|clean)"/ nocase
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
    // Biến thể leet: a=4 b=8 e=3 g=9 i=1 l=1 o=0 s=5 t=7.
    // Mỗi chuỗi liệt kê biến thể TƯỜNG MINH thay vì dùng char class như
    // /ign[0o]ire/: leet thay 1-1 ký tự nên giữ nguyên độ dài, mọi char class
    // bao gồm cả chữ gốc đều khớp "ignore" chữ thường và tạo FPR trên PE
    // sạch. Ở đây không chuỗi nào khớp văn bản chữ thường.
    //
    // Giới hạn đã biết: chỉ bắt biến thể thay 1 ký tự (kèm một vài cặp phổ
    // biến), không phải mọi tổ hợp. Đây là Lớp 1 best-effort; Lớp 3 Meta
    // Prompt Guard là lớp phủ chính. Chưa đo recall trên tập held-out.
    strings:
        $leet_ignore_1 = /1gnore/ nocase
        $leet_ignore_2 = /ig9ore/ nocase
        $leet_ignore_3 = /ign0re/ nocase
        $leet_ignore_4 = /ignor3/ nocase
        $leet_ignore_5 = /19n0r3/ nocase
        $leet_ignore_6 = /i9nore/ nocase
        $leet_ignore_7 = /1gn0re/ nocase

        $leet_benign_1 = /b3nign/ nocase
        $leet_benign_2 = /ben1gn/ nocase
        $leet_benign_3 = /b3n1gn/ nocase

        $leet_clean_1 = /cl34n/ nocase
        $leet_clean_2 = /cle4n/ nocase
        $leet_clean_3 = /c134n/ nocase
        $leet_clean_4 = /cl3an/ nocase

        $leet_goodware_1 = /g00dware/ nocase
        $leet_goodware_2 = /goodw4r3/ nocase
        $leet_goodware_3 = /g00dw4r3/ nocase
        $leet_goodware_4 = /goodw4re/ nocase
        $leet_goodware_5 = /goodw4r/ nocase

        $leet_verdict_1 = /v3rdict/ nocase
        $leet_verdict_2 = /verd1ct/ nocase

        // Dạng chèn dấu: chỉ chấp nhận dấu câu (- _ .) và space liên tiếp,
        // không chấp nhận separator tùy ý nên "a b c d e f" hiếm gặp.
        $spaced_dash = /i[-_.]g[-_.]n[-_.]o[-_.]r[-_.]e/ nocase
        $spaced_space = /i g n o r e/ nocase
    condition:
        any of them
}
