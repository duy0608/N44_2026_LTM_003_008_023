"""
FWGuard - Dashboard Firewall
============================

File này chứa toàn bộ giao diện Dashboard:
- HTML: cấu trúc trang, đăng nhập, bảng quy tắc, nhật ký chặn và cảnh báo quét port.
- CSS: bố cục, màu sắc và giao diện responsive.
- JavaScript: xác thực Bearer token, gọi API FastAPI và xử lý tương tác.
- FastAPI Router: trả giao diện về trình duyệt tại đường dẫn gốc "/".
"""

from fastapi import APIRouter
from fastapi.responses import HTMLResponse

router = APIRouter()

# ---------------------------------------------------------------------
# 1. CSS - Thiết kế giao diện Dashboard
# ---------------------------------------------------------------------

CSS = r"""
@import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700;800&family=Space+Grotesk:wght@500;600;700&display=swap');
:root {
    --bg:#f4f6fb;
    --ink:#172033;
    --muted:#7d879b;
    --line:#e8ebf2;
    --blue:#4169e1;
    --navy:#101a2d;
    --green:#169b72;
    --red:#df5261;
    --amber:#d97706}

* {
    box-sizing:border-box}

body {
    margin:0;
    background:var(--bg);
    color:var(--ink);
    font-family:'DM Sans',sans-serif;
    font-size:14px}

.app-shell {
    min-height:100vh}

.sidebar {
    width:244px;
    background:var(--navy);
    color:#fff;
    position:fixed;
    inset:0 auto 0 0;
    padding:28px 18px;
    display:flex;
    flex-direction:column;
    z-index:2}

.brand {
    display:flex;
    align-items:center;
    gap:12px;
    padding:0 9px 40px}

.brand-mark {
    width:38px;
    height:38px;
    border-radius:12px;
    background:linear-gradient(135deg,#6387ff,#3855c8);
    display:grid;
    place-items:center;
    font:700 22px 'Space Grotesk';
    box-shadow:0 7px 18px #2949a855}

.brand b {
    display:block;
    font:700 18px 'Space Grotesk';
    letter-spacing:.2px}

.brand small {
    font-size:9px;
    letter-spacing:1.7px;
    color:#8f9bb3}

.nav-label,.eyebrow {
    font-size:10px;
    font-weight:800;
    letter-spacing:1.4px;
    color:#8c98ad}

.nav-label {
    padding:0 12px 13px}

.nav-item {
    display:flex;
    align-items:center;
    justify-content:space-between;
    padding:12px 14px;
    color:#aab5c9;
    text-decoration:none;
    border-radius:9px;
    margin-bottom:5px;
    font-weight:600;
    cursor:pointer;
    border:0;
    background:transparent;
    width:100%;
    text-align:left;
    font-family:inherit;
    font-size:13px}

.nav-item-left {
    display:flex;
    align-items:center;
    gap:12px}

.nav-item-left span {
    font-size:17px;
    width:20px;
    text-align:center}

.nav-badge {
    background:#df5261;
    color:#fff;
    font-size:10px;
    font-weight:800;
    padding:2px 7px;
    border-radius:10px;
    display:none}

.nav-badge.show {
    display:inline-block}

.nav-item:hover {
    color:#fff;
    background:#1b2b47}

.nav-item.active {
    color:#fff;
    background:#263858;
    box-shadow:inset 3px 0 #6e8bff}

.sidebar-bottom {
    margin-top:auto;
    padding:16px 10px 0;
    border-top:1px solid #ffffff16;
    color:#8d9ab1}

.side-status {
    display:flex;
    align-items:center;
    gap:9px;
    color:#c6d0e1;
    font-size:12px;
    margin-bottom:9px}

.side-status i,.live i {
    width:7px;
    height:7px;
    border-radius:50%;
    background:#18bd8a;
    display:inline-block;
    box-shadow:0 0 0 4px #18bd8a20}

.sidebar-bottom small {
    font-size:11px;
    display:block;
    margin-bottom:10px}

.logout-btn {
    width:100%;
    padding:8px 10px;
    border-radius:7px;
    border:1px solid #ffffff22;
    background:#192742;
    color:#cbd5e1;
    font:600 11px 'DM Sans';
    cursor:pointer;
    display:none}

.logout-btn:hover {
    background:#243659;
    color:#fff}

.main {
    margin-left:244px;
    padding:34px 42px 24px;
    max-width:1700px}

.topbar {
    display:flex;
    justify-content:space-between;
    align-items:center;
    margin-bottom:25px}

.topbar h1 {
    font:700 27px 'Space Grotesk';
    margin:5px 0 0;
    letter-spacing:-.7px}

.top-actions {
    display:flex;
    align-items:center;
    gap:11px}

.live {
    font-size:10px;
    letter-spacing:1px;
    font-weight:800;
    color:#718096;
    display:flex;
    align-items:center;
    gap:9px;
    margin-right:8px}

.btn {
    border:0;
    border-radius:8px;
    padding:10px 15px;
    font:700 12px 'DM Sans';
    cursor:pointer;
    transition:.18s}

.btn:hover {
    transform:translateY(-1px)}

.btn:disabled {
    opacity:.6;
    cursor:not-allowed;
    transform:none}

.btn-primary {
    background:var(--blue);
    color:white;
    box-shadow:0 5px 13px #4169e12c}

.btn-ghost {
    background:#fff;
    color:#536078;
    border:1px solid var(--line)}

.notice {
    background:#edf3ff;
    border:1px solid #dce7ff;
    border-radius:10px;
    padding:13px 16px;
    display:flex;
    gap:12px;
    align-items:flex-start;
    margin-bottom:20px;
    color:#4e6391}

.notice-icon {
    font-size:19px}

.notice b {
    font-size:12px;
    color:#304c87}

.notice p {
    font-size:11px;
    margin:3px 0 0;
    color:#667da9}

.notice.warning {
    background:#fff6e8;
    border-color:#f8e4bd;
    color:#9b6b1e}

.notice.warning b {
    color:#93621b}

.stats-grid {
    display:grid;
    grid-template-columns:repeat(4,1fr);
    gap:16px;
    margin-bottom:22px}

.stat-card,.panel {
    background:#fff;
    border:1px solid var(--line);
    border-radius:12px;
    box-shadow:0 3px 12px #1b2a4a05}

.stat-card {
    padding:19px 20px}

.stat-top {
    display:flex;
    justify-content:space-between;
    align-items:center;
    color:#8b95a8;
    font-size:9px;
    font-weight:800;
    letter-spacing:1px}

.stat-icon {
    width:30px;
    height:30px;
    border-radius:9px;
    display:grid;
    place-items:center;
    font-size:17px}

.blue {
    background:#edf2ff;
    color:#5275e5}

.green {
    background:#e9f8f2;
    color:#169b72}

.red {
    background:#fff0f1;
    color:#df5261}

.violet {
    background:#f2edff;
    color:#8461d8}

.stat-card strong {
    display:block;
    font:700 28px 'Space Grotesk';
    margin:12px 0 2px}

.stat-card small {
    font-size:10px;
    color:#9aa3b3}

.status-value {
    font-size:19px!important;
    margin:17px 0 8px!important}

.panel {
    overflow:hidden;
    margin-bottom:20px}

.panel-heading {
    display:flex;
    align-items:center;
    justify-content:space-between;
    padding:22px 23px 17px}

.panel-heading h2 {
    font:700 17px 'Space Grotesk';
    margin:0 0 5px}

.panel-heading p {
    font-size:11px;
    color:#929bad;
    margin:0}

.toolbar {
    padding:0 23px 16px;
    display:flex;
    gap:10px;
    flex-wrap:wrap}

.search-wrap {
    height:36px;
    border:1px solid var(--line);
    border-radius:7px;
    display:flex;
    align-items:center;
    padding:0 11px;
    gap:8px;
    flex:1;
    min-width:210px;
    max-width:350px;
    color:#9aa4b5}

.search-wrap span {
    font-size:19px}

.search-wrap input {
    border:0;
    outline:0;
    width:100%;
    font:12px 'DM Sans';
    color:var(--ink)}

select {
    font:12px 'DM Sans';
    color:#657087;
    border:1px solid var(--line);
    border-radius:7px;
    background:#fff;
    padding:0 30px 0 11px;
    min-width:145px;
    height:36px;
    outline:0}

.table-wrap {
    overflow-x:auto}

table {
    width:100%;
    border-collapse:collapse;
    white-space:nowrap}

thead {
    background:#fafbfe}

th {
    text-align:left;
    color:#9aa3b3;
    font-size:9px;
    letter-spacing:.9px;
    font-weight:800;
    padding:12px 17px}

td {
    padding:14px 17px;
    border-top:1px solid #f0f2f6;
    font-size:11px;
    color:#59657b}

td:first-child,th:first-child {
    padding-left:23px}

.rule-name {
    font-weight:700;
    color:#27334a;
    font-size:12px}

.rule-id {
    font-size:9px;
    color:#a2aabb;
    margin-top:3px}

.condition {
    display:flex;
    gap:5px;
    align-items:center;
    flex-wrap:wrap;
    max-width:310px}

.chip {
    border-radius:5px;
    background:#f1f4f9;
    color:#657189;
    padding:4px 7px;
    font-size:10px;
    font-weight:600}

.direction {
    color:#738096;
    font-size:10px}

.pill {
    display:inline-flex;
    align-items:center;
    gap:6px;
    border-radius:20px;
    padding:5px 9px;
    font-size:10px;
    font-weight:700}

.pill.accept {
    background:#e9f8f2;
    color:#168d69}

.pill.drop {
    background:#fff0f1;
    color:#d84d5b}

.pill.enabled {
    background:#eaf8f2;
    color:#168d69}

.pill.disabled {
    background:#f1f2f5;
    color:#8791a2}

.right {
    text-align:right}

.row-actions {
    display:flex;
    justify-content:flex-end;
    gap:6px}

.icon-btn,.action-btn {
    border:1px solid var(--line);
    background:white;
    color:#758096;
    border-radius:6px;
    cursor:pointer;
    padding:6px 9px;
    font-size:11px}

.action-btn:hover,.icon-btn:hover {
    background:#f4f6fb;
    color:#31456e}

.empty {
    text-align:center;
    color:#9aa3b3;
    padding:35px}

.table-footer {
    border-top:1px solid #f0f2f6;
    padding:13px 23px;
    display:flex;
    justify-content:space-between;
    align-items:center;
    color:#9aa3b3;
    font-size:10px}

.text-btn {
    border:0;
    background:transparent;
    color:#5472d1;
    font:700 10px 'DM Sans';
    cursor:pointer}

footer {
    padding:10px 2px 20px;
    color:#a0a8b7;
    font-size:10px}

footer span {
    padding:0 5px;
    color:#c5cad4}

.view-section {
    display:none}

.view-section.active {
    display:block}

.top-ips {
    display:flex;
    gap:10px;
    flex-wrap:wrap;
    padding:0 23px 18px}

.ip-tag {
    background:#fff0f1;
    border:1px solid #ffd8dc;
    color:#b83745;
    border-radius:8px;
    padding:6px 11px;
    font-size:11px;
    font-weight:700}

.modal-backdrop {
    position:fixed;
    inset:0;
    background:#101a2d99;
    display:none;
    align-items:center;
    justify-content:center;
    padding:20px;
    z-index:20}

.modal-backdrop.show {
    display:flex}

.modal {
    background:#fff;
    border-radius:14px;
    width:min(620px,100%);
    padding:24px;
    box-shadow:0 20px 70px #0b142c55;
    max-height:94vh;
    overflow:auto}

.modal.login-box {
    width:min(400px,100%)}

.modal-head {
    display:flex;
    justify-content:space-between;
    align-items:flex-start;
    margin-bottom:20px}

.modal-head h2 {
    font:700 21px 'Space Grotesk';
    margin:5px 0}

.icon-btn {
    font-size:22px;
    padding:1px 8px;
    border:0}

.form-grid {
    display:grid;
    grid-template-columns:1fr 1fr;
    gap:14px}

.field {
    display:flex;
    flex-direction:column;
    gap:7px;
    color:#58647a;
    font-size:11px;
    font-weight:700;
    margin-bottom:14px}

.field input,.field select {
    height:39px;
    border:1px solid #e3e7ef;
    border-radius:7px;
    padding:0 11px;
    font:12px 'DM Sans';
    color:#29354a;
    outline:0;
    width:100%;
    background:white}

.field input:focus,.field select:focus {
    border-color:#7892ed;
    box-shadow:0 0 0 3px #4169e114}

.field select {
    min-width:0}

.check-field {
    display:flex;
    align-items:center;
    gap:9px;
    color:#58647a;
    font-size:11px;
    margin:2px 0 13px}

.check-field input {
    accent-color:#4169e1}

.form-hint {
    background:#f6f8fc;
    color:#8b95a8;
    border-radius:7px;
    padding:10px;
    font-size:10px;
    line-height:1.5}

.login-error {
    background:#fff0f1;
    color:#b83745;
    border:1px solid #ffd8dc;
    border-radius:7px;
    padding:9px 11px;
    font-size:11px;
    margin-bottom:12px;
    display:none}

.login-error.show {
    display:block}

.modal-actions {
    display:flex;
    justify-content:flex-end;
    gap:9px;
    margin-top:20px}

.toast {
    position:fixed;
    bottom:25px;
    right:25px;
    background:#17243b;
    color:#fff;
    padding:12px 17px;
    border-radius:8px;
    box-shadow:0 8px 25px #11182733;
    font-size:12px;
    opacity:0;
    transform:translateY(10px);
    pointer-events:none;
    transition:.2s;
    z-index:30;
    max-width:min(420px,90vw)}

.toast.show {
    opacity:1;
    transform:translateY(0)}

.toast.error {
    background:#a93243}

@media(max-width:1050px) {
    .main {
        padding:28px 24px;
        margin-left:210px}
    .sidebar {
        width:210px}
    .stats-grid {
        grid-template-columns:repeat(2,1fr)}
}

@media(max-width:700px) {
    .sidebar {
        position:static;
        width:auto;
        height:auto;
        padding:13px 17px}
    .brand {
        padding:0 0 12px}
    .nav-label,.sidebar-bottom {
        display:none}
    .main {
        margin:0;
        padding:22px 14px}
    .topbar {
        align-items:flex-start;
        gap:15px;
        flex-direction:column}
    .stats-grid {
        gap:9px}
    .form-grid {
        grid-template-columns:1fr;
        gap:0}
}
"""

# ---------------------------------------------------------------------
# 2. JavaScript - Xác thực token, gọi API và xử lý tương tác Dashboard
# ---------------------------------------------------------------------

JAVASCRIPT = r"""
const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => document.querySelectorAll(selector);

let rules = [];
let editingId = null;
let toastTimer = null;
let authToken = localStorage.getItem("fw_token") || "";

function escapeHtml(value) {
    return String(value ?? "").replace(/[&<>"']/g, (char) => ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#39;"
    })[char]);
}

function showToast(message, isError = false) {
    const element = $("#toast");
    element.textContent = message;
    element.className = "toast show" + (isError ? " error" : "");
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => {
        element.className = "toast";
    }, 3200);
}

function openLoginModal(message = "") {
    const errEl = $("#loginError");
    if (message) {
        errEl.textContent = message;
        errEl.classList.add("show");
    } else {
        errEl.classList.remove("show");
    }
    $("#loginModal").classList.add("show");
    setTimeout(() => $("#loginUser").focus(), 50);
}

function closeLoginModal() {
    $("#loginModal").classList.remove("show");
    $("#loginError").classList.remove("show");
}

async function api(path, options = {}) {
    const headers = {
        "Content-Type": "application/json",
        ...(authToken ? { "Authorization": `Bearer ${authToken}` } : {}),
        ...(options.headers || {})
    };

    const response = await fetch(path, {
        ...options,
        headers
    });

    if (response.status === 401) {
        localStorage.removeItem("fw_token");
        authToken = "";
        $("#logoutBtn").style.display = "none";
        openLoginModal("Vui lòng đăng nhập tài khoản quản trị để tiếp tục.");
        throw new Error("Yêu cầu đăng nhập (401)");
    }

    if (!response.ok) {
        let message = `HTTP ${response.status}`;
        try {
            const data = await response.json();
            message = data.detail || message;
        } catch (_) {}
        throw new Error(message);
    }

    if (authToken) {
        $("#logoutBtn").style.display = "block";
    }

    return response.status === 204 ? null : response.json();
}

// Chuyển tab trên thanh điều hướng bên trái
$$(".nav-item").forEach((btn) => {
    btn.addEventListener("click", () => {
        $$(".nav-item").forEach((b) => b.classList.remove("active"));
        btn.classList.add("active");

        const target = btn.dataset.tab;
        $$(".view-section").forEach((sec) => sec.classList.remove("active"));
        $(`#tab-${target}`).classList.add("active");

        if (target === "logs") loadLogs();
        if (target === "alerts") loadAlerts();
    });
});

// Hiển thị danh sách quy tắc firewall
function renderRules() {
    const keyword = $("#searchInput").value.toLowerCase();
    const actionFilter = $("#actionFilter").value;
    const stateFilter = $("#stateFilter").value;

    const filteredRules = rules.filter((rule) => {
        const searchable = [
            rule.name,
            rule.src_ip,
            rule.dst_ip,
            rule.port,
            rule.proto
        ].join(" ").toLowerCase();

        const matchesKeyword = !keyword || searchable.includes(keyword);
        const matchesAction = !actionFilter || rule.action === actionFilter;
        const matchesState = !stateFilter || String(Number(rule.enabled)) === stateFilter;
        return matchesKeyword && matchesAction && matchesState;
    });

    $("#ruleCount").textContent = `${filteredRules.length} / ${rules.length} quy tắc`;

    if (filteredRules.length === 0) {
        $("#rulesBody").innerHTML = `
            <tr>
                <td colspan="6" class="empty">
                    ${rules.length
                        ? "Không tìm thấy quy tắc phù hợp"
                        : "Chưa có quy tắc nào. Hãy bấm '+ Tạo quy tắc' để thêm rule đầu tiên."}
                </td>
            </tr>`;
        return;
    }

    $("#rulesBody").innerHTML = filteredRules.map((rule) => {
        const conditions = [
            rule.src_ip && `SRC ${escapeHtml(rule.src_ip)}`,
            rule.dst_ip && `DST ${escapeHtml(rule.dst_ip)}`,
            rule.port && `PORT ${escapeHtml(rule.port)}`,
            rule.proto !== "any" && escapeHtml(rule.proto.toUpperCase())
        ].filter(Boolean);

        const conditionHtml = conditions.length
            ? conditions.map((item) => `<span class="chip">${item}</span>`).join("")
            : '<span class="chip">Không giới hạn điều kiện</span>';

        return `
            <tr>
                <td>
                    <div class="rule-name">${escapeHtml(rule.name || "Quy tắc không tên")}</div>
                    <div class="rule-id">ID #${rule.id}</div>
                </td>
                <td><div class="condition">${conditionHtml}</div></td>
                <td>
                    <span class="direction">
                        ${rule.direction === "in" ? "↓ Inbound" : "↑ Outbound"}
                    </span>
                </td>
                <td>
                    <span class="pill ${rule.action}">
                        ${rule.action === "drop" ? "⊘ CHẶN" : "✓ CHO PHÉP"}
                    </span>
                </td>
                <td>
                    <span class="pill ${rule.enabled ? "enabled" : "disabled"}">
                        ${rule.enabled ? "● Đang bật" : "○ Đang tắt"}
                    </span>
                </td>
                <td>
                    <div class="row-actions">
                        <button class="action-btn" data-edit="${rule.id}">Sửa</button>
                        <button class="action-btn" data-toggle="${rule.id}">
                            ${rule.enabled ? "Tắt" : "Bật"}
                        </button>
                        <button class="action-btn" data-delete="${rule.id}">×</button>
                    </div>
                </td>
            </tr>`;
    }).join("");
}

// Cập nhật thống kê tổng quan
function renderStatus(status) {
    $("#totalRules").textContent = status.total_rules ?? 0;
    $("#enabledRules").textContent = status.enabled_rules ?? 0;
    $("#blockedPackets").textContent = Number(status.blocked_packets ?? 0).toLocaleString("vi-VN");

    $("#firewallState").textContent = status.firewall_active ? "ACTIVE" : "INACTIVE";
    $("#firewallSub").textContent = status.dry_run
        ? "DRY-RUN · Chưa tác động kernel"
        : "nftables · Kernel";

    $("#sideDot").style.background = status.firewall_active ? "#18bd8a" : "#e5a33b";
    $("#sideState").textContent = status.firewall_active
        ? "Firewall sẵn sàng"
        : "Chưa xác nhận bảng nftables";

    const alertCount = (status.recent_alerts || []).length;
    const badge = $("#alertBadge");
    if (alertCount > 0) {
        badge.textContent = alertCount;
        badge.classList.add("show");
    } else {
        badge.classList.remove("show");
    }

    const notice = $("#modeNotice");
    notice.className = "notice" + (status.dry_run ? "" : " warning");
    notice.querySelector("b").textContent = status.dry_run
        ? "Đang chạy chế độ DRY-RUN"
        : "Firewall đang chạy ở chế độ áp dụng thật";

    const adminText = (status.admin_ips && status.admin_ips.length)
        ? ` IP quản trị miễn trừ: ${status.admin_ips.join(", ")}.`
        : "";

    notice.querySelector("p").textContent = status.dry_run
        ? "Rule được lưu vào SQLite và sinh ruleset kiểm thử; chưa thay đổi firewall của hệ điều hành." + adminText
        : "Thay đổi rule được áp dụng trực tiếp vào bảng inet fwdash của nftables." + adminText;

    $("#updatedAt").textContent = "Cập nhật " + new Date().toLocaleTimeString("vi-VN");
}

// Tải dữ liệu tổng quan & rules
async function loadDashboard() {
    try {
        const [ruleData, statusData] = await Promise.all([
            api("/api/rules"),
            api("/api/status")
        ]);
        rules = ruleData;
        renderRules();
        renderStatus(statusData);
    } catch (error) {
        if (!String(error.message).includes("401")) {
            showToast("Lỗi kết nối backend: " + error.message, true);
        }
        $("#sideState").textContent = "Chưa kết nối phiên làm việc";
    }
}

// Tải nhật ký gói tin bị chặn
async function loadLogs() {
    try {
        const ipFilter = $("#logIpFilter").value.trim();
        const query = ipFilter ? `?limit=100&src_ip=${encodeURIComponent(ipFilter)}` : "?limit=100";
        const [logs, topIps] = await Promise.all([
            api("/api/logs" + query),
            api("/api/logs/top?limit=5")
        ]);

        $("#topBlockedIps").innerHTML = topIps.length
            ? topIps.map((item) => `<span class="ip-tag">${escapeHtml(item.src_ip)} · ${item.drops} gói</span>`).join("")
            : '<span style="font-size:11px;color:#9aa3b3">Chưa ghi nhận IP bị chặn nào.</span>';

        if (!logs.length) {
            $("#logsBody").innerHTML = '<tr><td colspan="6" class="empty">Chưa có bản ghi nhật ký nào.</td></tr>';
            return;
        }

        $("#logsBody").innerHTML = logs.map((l) => `
            <tr>
                <td>${escapeHtml(l.ts)}</td>
                <td><b>${escapeHtml(l.src_ip || "—")}</b>${l.sport ? ":" + l.sport : ""}</td>
                <td>${escapeHtml(l.dst_ip || "—")}</td>
                <td><span class="chip">${escapeHtml((l.proto || "—").toUpperCase())}</span></td>
                <td>${l.dport ?? "—"}</td>
                <td><span class="rule-id">#${l.rule_id ?? "—"}</span></td>
            </tr>`).join("");
    } catch (error) {
        if (!String(error.message).includes("401")) {
            showToast("Không tải được nhật ký: " + error.message, true);
        }
    }
}

// Tải cảnh báo quét port
async function loadAlerts() {
    try {
        const alerts = await api("/api/alerts?limit=50");
        if (!alerts.length) {
            $("#alertsBody").innerHTML = '<tr><td colspan="5" class="empty">Chưa phát hiện dấu hiệu quét port bất thường.</td></tr>';
            return;
        }
        $("#alertsBody").innerHTML = alerts.map((a) => `
            <tr>
                <td>${escapeHtml(a.ts)}</td>
                <td><b style="color:#d84d5b">${escapeHtml(a.src_ip)}</b></td>
                <td><span class="pill drop">${a.drops} gói bị chặn</span></td>
                <td><b>${a.distinct_ports}</b> port khác nhau</td>
                <td>Vượt ngưỡng ${a.threshold} gói / ${a.window_s}s</td>
            </tr>`).join("");
    } catch (error) {
        if (!String(error.message).includes("401")) {
            showToast("Không tải được cảnh báo: " + error.message, true);
        }
    }
}

// Modal Tạo / Sửa rule
function openModal(rule = null) {
    editingId = rule ? rule.id : null;
    $("#modalTitle").textContent = rule ? "Chỉnh sửa quy tắc" : "Tạo quy tắc mới";
    const form = $("#ruleForm");
    form.reset();

    if (rule) {
        ["name", "src_ip", "dst_ip", "port", "proto", "direction", "action"].forEach((field) => {
            form.elements[field].value = rule[field] ?? "";
        });
        form.elements.enabled.checked = Boolean(rule.enabled);
    } else {
        form.elements.enabled.checked = true;
    }
    $("#modal").classList.add("show");
}

function closeModal() {
    $("#modal").classList.remove("show");
    editingId = null;
}

function getFormData() {
    const form = $("#ruleForm");
    return {
        name: form.elements.name.value,
        src_ip: form.elements.src_ip.value.trim() || null,
        dst_ip: form.elements.dst_ip.value.trim() || null,
        port: form.elements.port.value.trim() || null,
        proto: form.elements.proto.value,
        direction: form.elements.direction.value,
        action: form.elements.action.value,
        enabled: form.elements.enabled.checked
    };
}

// Sự kiện Form đăng nhập
$("#loginForm").addEventListener("submit", async (event) => {
    event.preventDefault();
    const btn = $("#loginSubmitBtn");
    btn.disabled = true;
    btn.textContent = "Đang xác thực...";

    try {
        const res = await fetch("/api/login", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                username: $("#loginUser").value.trim(),
                password: $("#loginPass").value
            })
        });
        const data = await res.json();
        if (!res.ok) {
            throw new Error(data.detail || "Đăng nhập thất bại");
        }
        authToken = data.token;
        localStorage.setItem("fw_token", authToken);
        $("#loginPass").value = "";
        closeLoginModal();
        showToast("Đăng nhập thành công");
        await loadDashboard();
    } catch (err) {
        openLoginModal(err.message);
    } finally {
        btn.disabled = false;
        btn.textContent = "Đăng nhập";
    }
});

$("#logoutBtn").addEventListener("click", () => {
    localStorage.removeItem("fw_token");
    authToken = "";
    $("#logoutBtn").style.display = "none";
    openLoginModal("Đã đăng xuất phiên làm việc.");
});

// Sự kiện nút mở/đóng form rule
$("#addBtn").addEventListener("click", () => openModal());
$("#closeModal").addEventListener("click", closeModal);
$("#cancelBtn").addEventListener("click", closeModal);
$("#modal").addEventListener("click", (event) => {
    if (event.target === $("#modal")) closeModal();
});

// Submit tạo/sửa rule
$("#ruleForm").addEventListener("submit", async (event) => {
    event.preventDefault();
    const saveButton = $("#saveBtn");
    saveButton.disabled = true;
    saveButton.textContent = "Đang lưu...";

    try {
        const isEditing = editingId !== null;
        const path = isEditing ? `/api/rules/${editingId}` : "/api/rules";
        await api(path, {
            method: isEditing ? "PUT" : "POST",
            body: JSON.stringify(getFormData())
        });
        closeModal();
        showToast(isEditing ? "Đã cập nhật quy tắc" : "Đã tạo quy tắc");
        await loadDashboard();
    } catch (error) {
        showToast(error.message, true);
    } finally {
        saveButton.disabled = false;
        saveButton.textContent = "Lưu quy tắc";
    }
});

// Thao tác trên bảng rule
$("#rulesBody").addEventListener("click", async (event) => {
    const editId = event.target.dataset.edit;
    const toggleId = event.target.dataset.toggle;
    const deleteId = event.target.dataset.delete;

    try {
        if (editId) {
            const selectedRule = rules.find((r) => r.id === Number(editId));
            if (selectedRule) openModal(selectedRule);
            return;
        }
        if (toggleId) {
            const selectedRule = rules.find((r) => r.id === Number(toggleId));
            if (!selectedRule) return;
            await api(`/api/rules/${toggleId}/enabled`, {
                method: "PATCH",
                body: JSON.stringify({ enabled: !selectedRule.enabled })
            });
            showToast("Đã cập nhật trạng thái");
            await loadDashboard();
            return;
        }
        if (deleteId) {
            const selectedRule = rules.find((r) => r.id === Number(deleteId));
            if (!selectedRule) return;
            if (!confirm(`Xóa quy tắc "${selectedRule.name || "#" + selectedRule.id}"?`)) return;
            await api(`/api/rules/${deleteId}`, { method: "DELETE" });
            showToast("Đã xóa quy tắc");
            await loadDashboard();
        }
    } catch (error) {
        showToast(error.message, true);
    }
});

$("#searchInput").addEventListener("input", renderRules);
$("#actionFilter").addEventListener("change", renderRules);
$("#stateFilter").addEventListener("change", renderRules);
$("#refreshBtn").addEventListener("click", () => {
    loadDashboard();
    if ($("#tab-logs").classList.contains("active")) loadLogs();
    if ($("#tab-alerts").classList.contains("active")) loadAlerts();
});
$("#filterLogsBtn").addEventListener("click", loadLogs);

$("#syncBtn").addEventListener("click", async () => {
    const syncButton = $("#syncBtn");
    syncButton.disabled = true;
    try {
        const result = await api("/api/sync", { method: "POST" });
        showToast(`Đồng bộ thành công · ${result.active_rules} rule đang bật`);
        await loadDashboard();
    } catch (error) {
        showToast(error.message, true);
    } finally {
        syncButton.disabled = false;
    }
});

loadDashboard();
setInterval(loadDashboard, 15000);
"""

# ---------------------------------------------------------------------
# 3. HTML - Cấu trúc trang Dashboard
# ---------------------------------------------------------------------

HTML_TEMPLATE = r"""
<!doctype html>
<html lang="vi">
<head>
  <meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
  <meta name="theme-color" content="#0b1220"><title>FWGuard · Firewall Dashboard</title>
  <!-- DASHBOARD_CSS -->
</head>
<body>
<div class="app-shell">
  <aside class="sidebar">
    <div class="brand"><div class="brand-mark">F</div><div><b>FWGuard</b><small>NETWORK SECURITY</small></div></div>
    <div class="nav-label">QUẢN LÝ</div>
    <button class="nav-item active" data-tab="rules"><span class="nav-item-left"><span>≡</span> Quy tắc Firewall</span></button>
    <button class="nav-item" data-tab="logs"><span class="nav-item-left"><span>▤</span> Nhật ký chặn</span></button>
    <button class="nav-item" data-tab="alerts"><span class="nav-item-left"><span>⚠</span> Cảnh báo quét port</span><span class="nav-badge" id="alertBadge">0</span></button>
    <div class="sidebar-bottom">
      <div class="side-status"><i id="sideDot"></i><span id="sideState">Đang kiểm tra...</span></div>
      <small>Linux · nftables</small>
      <button class="logout-btn" id="logoutBtn">Đăng xuất</button>
    </div>
  </aside>
  <main class="main">
    <header class="topbar">
      <div><div class="eyebrow">NETWORK / FIREWALL</div><h1>Firewall Dashboard</h1></div>
      <div class="top-actions">
        <span class="live"><i></i> LIVE STATUS</span>
        <button class="btn btn-ghost" id="refreshBtn">↻ Làm mới</button>
        <button class="btn btn-primary" id="addBtn">＋ Tạo quy tắc</button>
      </div>
    </header>
    <section class="notice" id="modeNotice"><span class="notice-icon">ⓘ</span><div><b>Chế độ an toàn</b><p>Đang tải trạng thái thực tế từ backend...</p></div></section>
    <section class="stats-grid" id="overview">
      <article class="stat-card"><div class="stat-top"><span>TỔNG QUY TẮC</span><span class="stat-icon blue">≡</span></div><strong id="totalRules">—</strong><small>Tất cả quy tắc đã lưu</small></article>
      <article class="stat-card"><div class="stat-top"><span>ĐANG HOẠT ĐỘNG</span><span class="stat-icon green">✓</span></div><strong id="enabledRules">—</strong><small>Quy tắc đang được áp dụng</small></article>
      <article class="stat-card"><div class="stat-top"><span>GÓI TIN BỊ CHẶN</span><span class="stat-icon red">⊘</span></div><strong id="blockedPackets">—</strong><small>Tổng bộ đếm của rule DROP</small></article>
      <article class="stat-card"><div class="stat-top"><span>TRẠNG THÁI LÕI</span><span class="stat-icon violet">◈</span></div><strong class="status-value" id="firewallState">—</strong><small id="firewallSub">nftables</small></article>
    </section>

    <!-- Tab 1: Quy tắc Firewall -->
    <div class="view-section active" id="tab-rules">
      <section class="panel">
        <div class="panel-heading"><div><h2>Quy tắc Firewall</h2><p>Quản lý IP nguồn, IP đích, port và giao thức kết nối</p></div></div>
        <div class="toolbar">
          <div class="search-wrap"><span>⌕</span><input id="searchInput" placeholder="Tìm theo tên, IP, port..."></div>
          <select id="actionFilter"><option value="">Tất cả hành động</option><option value="accept">Cho phép</option><option value="drop">Chặn</option></select>
          <select id="stateFilter"><option value="">Mọi trạng thái</option><option value="1">Đang bật</option><option value="0">Đang tắt</option></select>
        </div>
        <div class="table-wrap">
          <table>
            <thead><tr><th>TÊN QUY TẮC</th><th>ĐIỀU KIỆN</th><th>HƯỚNG</th><th>HÀNH ĐỘNG</th><th>TRẠNG THÁI</th><th class="right">THAO TÁC</th></tr></thead>
            <tbody id="rulesBody"><tr><td colspan="6" class="empty">Đang tải dữ liệu...</td></tr></tbody>
          </table>
        </div>
        <div class="table-footer"><span id="ruleCount">0 quy tắc</span><button class="text-btn" id="syncBtn">⟳ Đồng bộ SQLite → nftables</button></div>
      </section>
    </div>

    <!-- Tab 2: Nhật ký gói tin bị chặn -->
    <div class="view-section" id="tab-logs">
      <section class="panel">
        <div class="panel-heading"><div><h2>Nhật ký kết nối bị chặn (FWD-DROP)</h2><p>Ghi nhận từ nhân Linux khi gói tin khớp rule DROP</p></div></div>
        <div class="top-ips" id="topBlockedIps"></div>
        <div class="toolbar">
          <div class="search-wrap"><span>⌕</span><input id="logIpFilter" placeholder="Lọc chính xác theo IP nguồn (vd: 192.168.56.20)..."></div>
          <button class="btn btn-ghost" id="filterLogsBtn">Lọc nhật ký</button>
        </div>
        <div class="table-wrap">
          <table>
            <thead><tr><th>THỜI GIAN (UTC)</th><th>IP NGUỒN</th><th>IP ĐÍCH</th><th>GIAO THỨC</th><th>PORT ĐÍCH</th><th>MÃ RULE</th></tr></thead>
            <tbody id="logsBody"><tr><td colspan="6" class="empty">Đang tải nhật ký...</td></tr></tbody>
          </table>
        </div>
      </section>
    </div>

    <!-- Tab 3: Cảnh báo quét port -->
    <div class="view-section" id="tab-alerts">
      <section class="panel">
        <div class="panel-heading"><div><h2>Cảnh báo dò quét Port</h2><p>Tự động phát hiện IP gửi nhiều gói bị chặn trong cửa sổ thời gian ngắn</p></div></div>
        <div class="table-wrap">
          <table>
            <thead><tr><th>THỜI GIAN (UTC)</th><th>IP NGHI VẤN</th><th>SỐ GÓI BỊ CHẶN</th><th>SỐ PORT QUÉT</th><th>CHI TIẾT NGƯỠNG</th></tr></thead>
            <tbody id="alertsBody"><tr><td colspan="5" class="empty">Đang kiểm tra cảnh báo...</td></tr></tbody>
          </table>
        </div>
      </section>
    </div>

    <footer>FWGuard <span>·</span> FastAPI + SQLite + nftables <span>·</span> <span id="updatedAt">Chưa cập nhật</span></footer>
  </main>
</div>

<!-- Modal Tạo / Sửa quy tắc -->
<div class="modal-backdrop" id="modal">
  <section class="modal">
    <div class="modal-head"><div><div class="eyebrow">RULE CONFIGURATION</div><h2 id="modalTitle">Tạo quy tắc mới</h2></div><button class="icon-btn" id="closeModal" aria-label="Đóng">×</button></div>
    <form id="ruleForm">
      <label class="field">Tên quy tắc<input name="name" maxlength="100" placeholder="Ví dụ: Chặn SSH từ IP lạ"></label>
      <div class="form-grid">
        <label class="field">IP nguồn / CIDR<input name="src_ip" placeholder="203.0.113.10 hoặc 10.0.0.0/24"></label>
        <label class="field">IP đích / CIDR<input name="dst_ip" placeholder="Để trống nếu không lọc"></label>
        <label class="field">Port<input name="port" placeholder="22 hoặc 8000-8100"></label>
        <label class="field">Giao thức<select name="proto"><option value="tcp">TCP</option><option value="udp">UDP</option><option value="any">Bất kỳ (không lọc port)</option></select></label>
        <label class="field">Hướng kết nối<select name="direction"><option value="in">Inbound · Đi vào</option><option value="out">Outbound · Đi ra</option></select></label>
        <label class="field">Hành động<select name="action"><option value="drop">DROP · Chặn</option><option value="accept">ACCEPT · Cho phép</option></select></label>
      </div>
      <label class="check-field"><input type="checkbox" name="enabled" checked><span>Bật quy tắc ngay sau khi lưu</span></label>
      <div class="form-hint">Cần ít nhất một điều kiện IP, port hoặc giao thức. Khi nhập port, hãy chọn TCP hoặc UDP.</div>
      <div class="modal-actions"><button type="button" class="btn btn-ghost" id="cancelBtn">Hủy</button><button type="submit" class="btn btn-primary" id="saveBtn">Lưu quy tắc</button></div>
    </form>
  </section>
</div>

<!-- Modal Đăng nhập -->
<div class="modal-backdrop" id="loginModal">
  <section class="modal login-box">
    <div class="modal-head"><div><div class="eyebrow">AUTHENTICATION</div><h2>Đăng nhập FWGuard</h2></div></div>
    <div class="login-error" id="loginError"></div>
    <form id="loginForm">
      <label class="field">Tên đăng nhập<input id="loginUser" value="admin" required></label>
      <label class="field">Mật khẩu quản trị<input id="loginPass" type="password" placeholder="Nhập mật khẩu từ console" required></label>
      <div class="form-hint">Mật khẩu khởi tạo lần đầu được in trên màn hình terminal khi chạy backend (hoặc qua biến FW_ADMIN_PASSWORD).</div>
      <div class="modal-actions"><button type="submit" class="btn btn-primary" id="loginSubmitBtn" style="width:100%">Đăng nhập</button></div>
    </form>
  </section>
</div>

<div class="toast" id="toast"></div>
<!-- DASHBOARD_JS -->
</body></html>
"""

# ---------------------------------------------------------------------
# 4. FastAPI Route - Nhúng CSS và JavaScript vào HTML
# ---------------------------------------------------------------------

@router.get("/", response_class=HTMLResponse, include_in_schema=False)
def dashboard_home():
    """Hiển thị trang Firewall Dashboard."""
    page = HTML_TEMPLATE.replace(
        "<!-- DASHBOARD_CSS -->",
        "<style>\n" + CSS + "\n</style>"
    )
    page = page.replace(
        "<!-- DASHBOARD_JS -->",
        "<script>\n" + JAVASCRIPT + "\n</script>"
    )
    return HTMLResponse(content=page)