"""
FWGuard - Dashboard Firewall
============================

File này chứa toàn bộ giao diện Dashboard:
- HTML: cấu trúc trang và các biểu mẫu.
- CSS: bố cục, màu sắc và giao diện responsive.
- JavaScript: gọi API và xử lý tương tác.
- FastAPI Router: trả giao diện về trình duyệt.

Chỉ cần include_router(router) trong backend/app/main.py.
"""

from fastapi import APIRouter
from fastapi.responses import HTMLResponse

router = APIRouter()

# ---------------------------------------------------------------------
# 1. CSS - Thiết kế giao diện Dashboard
# ---------------------------------------------------------------------

CSS = r"""
@import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;
    500;
    600;
    700;
    800&family=Space+Grotesk:wght@500;
    600;
    700&display=swap');
:root {
    --bg:#f4f6fb;
    --ink:#172033;
    --muted:#7d879b;
    --line:#e8ebf2;
    --blue:#4169e1;
    --navy:#101a2d;
    --green:#169b72;
    --red:#df5261}

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
    padding:0 9px 45px}

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
    gap:13px;
    padding:13px 14px;
    color:#aab5c9;
    text-decoration:none;
    border-radius:9px;
    margin-bottom:5px;
    font-weight:600}

.nav-item span {
    font-size:19px;
    width:20px;
    text-align:center}

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
    font-size:11px}

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
    overflow:hidden}

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
    gap:10px}

.search-wrap {
    height:36px;
    border:1px solid var(--line);
    border-radius:7px;
    display:flex;
    align-items:center;
    padding:0 11px;
    gap:8px;
    flex:1;
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
    font-size:10px}

.chip.protocol {
    background:#eef3ff;
    color:#5571c6}

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
    padding:20px 2px;
    color:#a0a8b7;
    font-size:10px}

footer span {
    padding:0 5px;
    color:#c5cad4}

.mobile-add {
    display:none}

.modal-backdrop {
    position:fixed;
    inset:0;
    background:#101a2d88;
    display:none;
    align-items:center;
    justify-content:center;
    padding:20px;
    z-index:5}

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

.modal-head {
    display:flex;
    justify-content:space-between;
    align-items:flex-start;
    margin-bottom:22px}

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

.field.full {
    margin-bottom:14px}

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
    z-index:10;
    max-width: min(420px,90vw)}

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
    padding:0}

.nav-label,.nav-item,.sidebar-bottom {
    display:none}

.main {
    margin:0;
    padding:22px 14px}

.topbar {
    align-items:flex-start;
    gap:15px;
    flex-direction:column}

.topbar h1 {
    font-size:23px}

.top-actions {
    width:100%;
    flex-wrap:wrap}

.live {
    margin-right:auto}

.top-actions .btn {
    padding:9px 11px}

.stats-grid {
    gap:9px}

.stat-card {
    padding:14px}

.stat-card strong {
    font-size:24px}

.stat-top {
    font-size:8px}

.panel-heading {
    padding:17px 15px}

.panel-heading p {
    max-width:230px;
    line-height:1.5}

.mobile-add {
    display:block}

.top-actions #addBtn {
    display:none}

.toolbar {
    padding:0 15px 13px;
    flex-wrap:wrap}

.search-wrap {
    max-width:none;
    flex-basis:100%}

.toolbar select {
    flex:1;
    min-width:0;
    height:35px}

.table-footer {
    padding:12px 15px}

.form-grid {
    grid-template-columns:1fr;
    gap:0}

.modal {
    padding:19px}

.notice {
    margin-bottom:13px}

}
"""

# ---------------------------------------------------------------------
# 2. JavaScript - Gọi API và xử lý các thao tác trên Dashboard
# ---------------------------------------------------------------------

JAVASCRIPT = r"""
// Gọi API FastAPI và xử lý lỗi HTTP.
const $ = (selector) => document.querySelector(selector);

let rules = [];
let editingId = null;
let toastTimer = null;

async function api(path, options = {}) {
    const response = await fetch(path, {
        ...options,
        headers: {
            "Content-Type": "application/json",
            ...(options.headers || {})
        }
    });

    if (!response.ok) {
        let message = `HTTP ${response.status}`;
        try {
            const data = await response.json();
            message = data.detail || message;
        } catch (_) {
            // Giữ thông báo HTTP mặc định nếu response không phải JSON.
        }
        throw new Error(message);
    }

    return response.status === 204 ? null : response.json();
}

// Chống chèn HTML khi hiển thị dữ liệu do người dùng nhập.
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

// Hiển thị danh sách rule, đồng thời áp dụng tìm kiếm và bộ lọc.
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
        const matchesState = !stateFilter ||
            String(Number(rule.enabled)) === stateFilter;

        return matchesKeyword && matchesAction && matchesState;
    });

    $("#ruleCount").textContent =
        `${filteredRules.length} / ${rules.length} quy tắc`;

    if (filteredRules.length === 0) {
        $("#rulesBody").innerHTML = `
            <tr>
                <td colspan="6" class="empty">
                    ${rules.length
                        ? "Không tìm thấy quy tắc phù hợp"
                        : "Chưa có quy tắc nào. Hãy tạo rule đầu tiên."}
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

// Cập nhật các thẻ thống kê và trạng thái firewall.
function renderStatus(status) {
    $("#totalRules").textContent = status.total_rules ?? 0;
    $("#enabledRules").textContent = status.enabled_rules ?? 0;
    $("#blockedPackets").textContent =
        Number(status.blocked_packets ?? 0).toLocaleString("vi-VN");

    $("#firewallState").textContent =
        status.firewall_active ? "ACTIVE" : "INACTIVE";

    $("#firewallSub").textContent = status.dry_run
        ? "DRY-RUN · Chưa tác động kernel"
        : "nftables · Kernel";

    $("#sideDot").style.background =
        status.firewall_active ? "#18bd8a" : "#e5a33b";

    $("#sideState").textContent = status.firewall_active
        ? "Firewall sẵn sàng"
        : "Chưa xác nhận bảng nftables";

    const notice = $("#modeNotice");
    notice.className = "notice" + (status.dry_run ? "" : " warning");

    notice.querySelector("b").textContent = status.dry_run
        ? "Đang chạy chế độ DRY-RUN"
        : "Firewall đang chạy ở chế độ áp dụng thật";

    notice.querySelector("p").textContent = status.dry_run
        ? "Rule được lưu vào SQLite và sinh ruleset kiểm thử; chưa thay đổi firewall của hệ điều hành."
        : "Thay đổi rule sẽ được áp dụng trực tiếp vào nftables. Chỉ thao tác khi đã cấu hình IP quản trị an toàn.";

    $("#updatedAt").textContent =
        "Cập nhật " + new Date().toLocaleTimeString("vi-VN");
}

// Tải dữ liệu rule và trạng thái từ backend.
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
        showToast("Không kết nối được backend: " + error.message, true);
        $("#sideState").textContent = "Backend không phản hồi";
    }
}

// Mở form thêm mới hoặc chỉnh sửa rule.
function openModal(rule = null) {
    editingId = rule ? rule.id : null;

    $("#modalTitle").textContent = rule
        ? "Chỉnh sửa quy tắc"
        : "Tạo quy tắc mới";

    const form = $("#ruleForm");
    form.reset();

    if (rule) {
        ["name", "src_ip", "dst_ip", "port", "proto", "direction", "action"]
            .forEach((field) => {
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

// Chuyển dữ liệu trong form thành JSON gửi lên FastAPI.
function getFormData() {
    const form = $("#ruleForm");

    return {
        name: form.elements.name.value,
        src_ip: form.elements.src_ip.value || null,
        dst_ip: form.elements.dst_ip.value || null,
        port: form.elements.port.value || null,
        proto: form.elements.proto.value,
        direction: form.elements.direction.value,
        action: form.elements.action.value,
        enabled: form.elements.enabled.checked
    };
}

// Gắn sự kiện cho các nút mở/đóng form.
$("#addBtn").addEventListener("click", () => openModal());
$("#addBtn2").addEventListener("click", () => openModal());
$("#closeModal").addEventListener("click", closeModal);
$("#cancelBtn").addEventListener("click", closeModal);

$("#modal").addEventListener("click", (event) => {
    if (event.target === $("#modal")) {
        closeModal();
    }
});

// Tạo mới hoặc cập nhật rule.
$("#ruleForm").addEventListener("submit", async (event) => {
    event.preventDefault();

    const saveButton = $("#saveBtn");
    saveButton.disabled = true;
    saveButton.textContent = "Đang lưu...";

    try {
        const isEditing = editingId !== null;
        const path = isEditing
            ? `/api/rules/${editingId}`
            : "/api/rules";

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

// Xử lý các nút Sửa, Bật/Tắt và Xóa trong bảng.
$("#rulesBody").addEventListener("click", async (event) => {
    const editId = event.target.dataset.edit;
    const toggleId = event.target.dataset.toggle;
    const deleteId = event.target.dataset.delete;

    try {
        if (editId) {
            const selectedRule = rules.find(
                (rule) => rule.id === Number(editId)
            );

            if (selectedRule) openModal(selectedRule);
            return;
        }

        if (toggleId) {
            const selectedRule = rules.find(
                (rule) => rule.id === Number(toggleId)
            );

            if (!selectedRule) return;

            await api(`/api/rules/${toggleId}/enabled`, {
                method: "PATCH",
                body: JSON.stringify({
                    enabled: !selectedRule.enabled
                })
            });

            showToast("Đã cập nhật trạng thái");
            await loadDashboard();
            return;
        }

        if (deleteId) {
            const selectedRule = rules.find(
                (rule) => rule.id === Number(deleteId)
            );

            if (!selectedRule) return;

            const confirmed = confirm(
                `Xóa quy tắc "${selectedRule.name || "#" + selectedRule.id}"?`
            );

            if (!confirmed) return;

            await api(`/api/rules/${deleteId}`, {
                method: "DELETE"
            });

            showToast("Đã xóa quy tắc");
            await loadDashboard();
        }
    } catch (error) {
        showToast(error.message, true);
    }
});

// Tìm kiếm và lọc rule ngay trên giao diện.
$("#searchInput").addEventListener("input", renderRules);
$("#actionFilter").addEventListener("change", renderRules);
$("#stateFilter").addEventListener("change", renderRules);

// Làm mới dữ liệu và đồng bộ SQLite với nftables.
$("#refreshBtn").addEventListener("click", loadDashboard);

$("#syncBtn").addEventListener("click", async () => {
    const syncButton = $("#syncBtn");
    syncButton.disabled = true;

    try {
        const result = await api("/api/sync", {
            method: "POST"
        });

        showToast(
            `Đồng bộ thành công · ${result.active_rules} rule đang bật`
        );

        await loadDashboard();
    } catch (error) {
        showToast(error.message, true);
    } finally {
        syncButton.disabled = false;
    }
});

// Tải lần đầu và tự làm mới dữ liệu mỗi 15 giây.
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
    <a class="nav-item active" href="#overview"><span>▦</span> Tổng quan</a>
    <a class="nav-item" href="#rules"><span>≡</span> Quy tắc Firewall</a>
    <div class="sidebar-bottom"><div class="side-status"><i id="sideDot"></i><span id="sideState">Đang kiểm tra...</span></div><small>Linux · nftables</small></div>
  </aside>
  <main class="main">
    <header class="topbar"><div><div class="eyebrow">NETWORK / FIREWALL</div><h1>Firewall Dashboard</h1></div>
      <div class="top-actions"><span class="live"><i></i> LIVE STATUS</span><button class="btn btn-ghost" id="refreshBtn">↻ Làm mới</button><button class="btn btn-primary" id="addBtn">＋ Tạo quy tắc</button></div>
    </header>
    <section class="notice" id="modeNotice"><span class="notice-icon">ⓘ</span><div><b>Chế độ an toàn</b><p>Đang tải trạng thái thực tế từ backend...</p></div></section>
    <section class="stats-grid" id="overview">
      <article class="stat-card"><div class="stat-top"><span>TỔNG QUY TẮC</span><span class="stat-icon blue">≡</span></div><strong id="totalRules">—</strong><small>Tất cả quy tắc đã lưu</small></article>
      <article class="stat-card"><div class="stat-top"><span>ĐANG HOẠT ĐỘNG</span><span class="stat-icon green">✓</span></div><strong id="enabledRules">—</strong><small>Quy tắc đang được áp dụng</small></article>
      <article class="stat-card"><div class="stat-top"><span>GÓI TIN BỊ CHẶN</span><span class="stat-icon red">⊘</span></div><strong id="blockedPackets">—</strong><small>Tổng bộ đếm của rule DROP</small></article>
      <article class="stat-card"><div class="stat-top"><span>TRẠNG THÁI LÕI</span><span class="stat-icon violet">◈</span></div><strong class="status-value" id="firewallState">—</strong><small id="firewallSub">nftables</small></article>
    </section>
    <section class="panel" id="rules">
      <div class="panel-heading"><div><h2>Quy tắc Firewall</h2><p>Quản lý IP nguồn, IP đích, port và giao thức kết nối</p></div><button class="btn btn-primary mobile-add" id="addBtn2">＋ Thêm rule</button></div>
      <div class="toolbar"><div class="search-wrap"><span>⌕</span><input id="searchInput" placeholder="Tìm theo tên, IP, port..."></div>
        <select id="actionFilter"><option value="">Tất cả hành động</option><option value="accept">Cho phép</option><option value="drop">Chặn</option></select>
        <select id="stateFilter"><option value="">Mọi trạng thái</option><option value="1">Đang bật</option><option value="0">Đang tắt</option></select>
      </div>
      <div class="table-wrap"><table><thead><tr><th>TÊN QUY TẮC</th><th>ĐIỀU KIỆN</th><th>HƯỚNG</th><th>HÀNH ĐỘNG</th><th>TRẠNG THÁI</th><th class="right">THAO TÁC</th></tr></thead><tbody id="rulesBody"><tr><td colspan="6" class="empty">Đang tải dữ liệu...</td></tr></tbody></table></div>
      <div class="table-footer"><span id="ruleCount">0 quy tắc</span><button class="text-btn" id="syncBtn">⟳ Đồng bộ SQLite → nftables</button></div>
    </section>
    <footer>FWGuard <span>·</span> FastAPI + SQLite + nftables <span>·</span> <span id="updatedAt">Chưa cập nhật</span></footer>
  </main>
</div>
<div class="modal-backdrop" id="modal">
  <section class="modal">
    <div class="modal-head"><div><div class="eyebrow">RULE CONFIGURATION</div><h2 id="modalTitle">Tạo quy tắc mới</h2></div><button class="icon-btn" id="closeModal" aria-label="Đóng">×</button></div>
    <form id="ruleForm">
      <label class="field full">Tên quy tắc<input name="name" maxlength="100" placeholder="Ví dụ: Chặn SSH từ IP lạ"></label>
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
        "<style>\\n" + CSS + "\\n</style>"
    )

    page = page.replace(
        "<!-- DASHBOARD_JS -->",
        "<script>\\n" + JAVASCRIPT + "\\n</script>"
    )

    return HTMLResponse(content=page)
