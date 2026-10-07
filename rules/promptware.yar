// Bộ luật YARA tĩnh — Lớp 1 (T04, spec v1.4.0 §3.2.1).
//
// Gồm hai phần, tách bạch:
//
// 1. `Static_Promptware_InstructionBypass` — rule tham chiếu, port NGUYÊN VĂN từ
//    spec §3.2.1 (toàn bộ regex, cờ `nocase`, bốn khoá meta). Không thêm/bớt
//    string, không nới lỏng điều kiện: spec là nguồn chuẩn, đổi rule này phải đổi
//    spec + ADR trước.
// 2. Họ `Promptware_*` — rule MỞ RỘNG (ngoài spec), mỗi rule khai `version`
//    riêng (`ext-*`) để provenance không ghi nhầm "1.4.0". Chưa có held-out set
//    và chưa đo FPR trên PE sạch thật: chỉ có test âm tính tổng hợp
//    (`tests/test_yara_scanner.py`), KHÔNG phải bằng chứng hiệu quả/FPR. Mọi
//    string phải neo vào ngữ cảnh chỉ thị (động từ mệnh lệnh / tiền tố
//    delimiter), tránh cụm trung tính như "debug mode on", "end of data",
//    `<result>` — vốn xuất hiện trong PE hợp lệ.
//
// Lưu ý: một finding YARA bất kỳ tại cùng provenance cũng bật
// `InstructionOverrideContext` (§3.4, `pipeline.py`), nên thêm rule rộng làm
// yếu bộ lọc FPR "malware command ≠ promptware". Thêm/nới string ở phần 2 phải
// kèm test âm tính.
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

// --- Phần 2: rule mở rộng (ngoài spec) -------------------------------------

rule Promptware_InstructionBypassExt {
    meta:
        description = "Extended instruction-bypass phrasing not covered by the spec reference rule"
        threat_level = "HIGH"
        mitre_atlas = "AML.T0051.001"
        version = "ext-1.0.0"
    strings:
        $override_reset  = /reset\s+your\s+(instructions|context|prompt)/ nocase
        $verdict_goodware = /classify\s+(this\s+|the\s+)?(file|sample|binary|program|it)\s+as\s+goodware/ nocase
        $verdict_no_ioc  = /do\s+not\s+(report|mention)\s+(the\s+|any\s+)?(c2|command[-\s]and[-\s]control|indicators?\s+of\s+compromise|iocs?|exfiltration)/ nocase
        $verdict_no_mal  = /(conclude|report|state|say|declare)\s+(that\s+)?(there\s+is\s+)?no\s+malicious\s+(behavior|activity)/ nocase
        $role_acting     = /you\s+(are|will\s+be)\s+acting\s+as\s+(a\s+)?(trusted\s+)?(admin|analyst|supervisor)/ nocase
        $role_clearance  = /(has|with|granted)\s+admin\s+clearance/ nocase
        $role_approved   = /(is|in|on)\s+the\s+(approved|whitelisted)\s+software\s+list/ nocase
    condition:
        any of them
}

rule Promptware_FakeStructure {
    meta:
        description = "Detects fake verdict/structure injection"
        threat_level = "HIGH"
        mitre_atlas = "AML.T0051.001"
        version = "ext-1.0.0"
    strings:
        // Chỉ dạng JSON có trích dẫn khoá. Không khớp `isMalicious: false` hay
        // `malicious = false` (cấu hình/log hợp lệ).
        $verdict_json = /"malicious"\s*:\s*false/ nocase
        // Chỉ tag giả dạng verdict của analyzer; không dùng `<result>` trần
        // (xuất hiện trong XML/manifest hợp lệ).
        $verdict_tag  = /<\/?(official_verdict|analysis_result)[^>]*>/ nocase
        // Chỉ dạng có trích dẫn kiểu JSON. Dạng thô `verdict: benign` đã do
        // rule spec §3.2.1 `$verdict_3` bắt; để ở đây sẽ khiến cùng một mảng
        // chuỗi rơi vào hai rule nên `_dedupe_yara_findings` không gộp được,
        // và sinh FPR trên PE sạch.
        $verdict_safe = /"verdict"\s*:\s*"(benign|safe|clean)"/ nocase
        // Bắt buộc delimiter `===`; "end of data"/"analysis complete" trần là
        // thông điệp thường gặp của phần mềm hợp lệ.
        $end_marker   = /={3,}\s*end\s+(of\s+)?(report|data|analysis)/ nocase
        // Chỉ dạng JSON có trích dẫn; `Threat level: None` trần là chuỗi UI của
        // sản phẩm AV hợp lệ.
        $threat_none  = /"threat_?level"\s*:\s*"(none|safe)"/ nocase
        // Khẳng định về chính mẫu đang phân tích, không phải cụm "legitimate
        // software" trần (chuỗi UI của sản phẩm AV/installer).
        $whitelist    = /this\s+(file|sample|binary|program|executable)\s+(is|was|has\s+been)\s+(whitelisted|pre-?cleared|(a\s+)?(legitimate|trusted)\s+(software|scanner|sample|file))/ nocase
    condition:
        any of them
}

rule Promptware_Roleplay {
    meta:
        description = "Detects authority/roleplay injection"
        threat_level = "HIGH"
        mitre_atlas = "AML.T0051.001"
        version = "ext-1.0.0"
    strings:
        // `I'm` không có khoảng trắng trước `'m`; phải kèm chỉ thị theo sau.
        $auth_1 = /I(\s+am|'m)\s+(the\s+)?(security\s+lead|admin|analyst|supervisor)\b.{0,80}(authori[sz]e|instruct|approve|clear|benign|clean|safe|ignore|skip|suppress|do\s+not|don't)/ nocase
        $auth_2 = /(authori[sz]e|instruct|clear(ed)?)\s+you\s+to\s+(ignore|skip|classify|mark|report|output|treat|suppress|disregard|say|declare|label)/ nocase
        $auth_3 = /(entering|switch(ing|ed)?\s+to|now\s+in|enable[sd]?)\s+(a\s+)?(maintenance|developer|debug)\s+mode\b.{0,60}(ignore|skip|disable|bypass|no\s+(alerts?|restrictions?|filters?)|benign|clean|safe)/ nocase
        $auth_4 = /this\s+(file|sample|binary|program|executable)\s+(is|was|has\s+been)\s+(pre-?cleared|(pre-?)?approved|whitelisted)|pre-?cleared\s+(by|sample|file)/ nocase
        // Không có "warnings": "suppress warnings" là tuỳ chọn compiler/log hợp lệ.
        $auth_5 = /suppress\s+(all\s+)?(malware\s+)?(alerts|detections)/ nocase
        $auth_6 = /(red[-\s]?team|penetration\s+test|pentest)\b.{0,40}(mark|treat|classify|report|label|ignore)\b.{0,30}(benign|clean|safe|alerts|detections)/ nocase
    condition:
        any of them
}

rule Promptware_Evasion {
    meta:
        description = "Detects spacing/leet evasion of instruction-bypass"
        threat_level = "HIGH"
        mitre_atlas = "AML.T0051.001"
        version = "ext-1.0.0"
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

        // `goodw4r` bao `goodw4re`/`goodw4r3`; `g00dw4r` bao `g00dw4r3`.
        $leet_goodware_1 = /g00dware/ nocase
        $leet_goodware_2 = /goodw4r/ nocase
        $leet_goodware_3 = /g00dw4r/ nocase

        $leet_verdict_1 = /v3rdict/ nocase
        $leet_verdict_2 = /verd1ct/ nocase

        // Dạng chèn dấu: chỉ chấp nhận dấu câu (- _ .) và space liên tiếp,
        // không chấp nhận separator tùy ý nên "a b c d e f" hiếm gặp.
        $spaced_dash = /i[-_.]g[-_.]n[-_.]o[-_.]r[-_.]e/ nocase
        $spaced_space = /i g n o r e/ nocase
    condition:
        any of them
}
