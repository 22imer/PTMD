// Bộ luật YARA động — module Cuckoo (T04, spec v1.4.0 §3.2.2).
//
// Rule dưới đây được port nguyên văn từ spec §3.2.2
// (`Dynamic_Cuckoo_Network_Telemetry`). File CHỈ biên dịch được khi YARA được
// dựng với `--enable-cuckoo`; build thiếu cờ đó trả `unknown module "cuckoo"`.
// Vì vậy rule này nằm tách khỏi `rules/promptware.yar` (ruleset tĩnh luôn biên
// dịch được), và `guardrail.yara_scanner` chỉ nạp file này khi phép thăm dò
// module Cuckoo thành công — nếu không, scanner Cuckoo bị vô hiệu kèm cờ cấu
// hình `cuckoo_unavailable`, không thay thế bằng cơ chế ngầm (spec §3.2.2).
//
// Report CAPEv2 được nạp qua external variable `cuckoo` (đường dẫn file JSON
// report), không phải qua module-data.

import "cuckoo"

rule Dynamic_Cuckoo_Network_Telemetry {
    meta:
        mitre_atlas = "AML.T0051.001"
    condition:
        cuckoo.network.http_user_agent(/.*(ignore|bypass).*prompt.*/) or
        cuckoo.network.http_request(/.*(override_role|verdict=benign).*/)
}
