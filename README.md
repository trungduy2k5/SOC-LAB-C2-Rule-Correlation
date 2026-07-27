# SOC-LAB-C2-Rule-Correlation
# 🛡️ SIEM Detection Rules & Correlation Engine (Splunk + Sysmon + Suricata)

Đề tài xây dựng hệ thống **SIEM (Splunk Enterprise)** và các **Quy tắc Tương quan (Correlation Rules)** nâng cao nhằm phát hiện các hành vi tấn công mạng tinh vi, đặc biệt tập trung vào các giai đoạn **Kênh điều khiển C2 (Command & Control)**, **Chuyển dịch ngang (Lateral Movement)**, và **Đánh cắp dữ liệu (Data Exfiltration)**.

Hệ thống kết hợp kỹ thuật phòng thủ tương quan chéo (Cross-source Correlation) giữa log **hành vi tiến trình máy trạm (Windows Sysmon)** và **lưu lượng mạng (Suricata NIDS)**, đi kèm kịch bản sinh log thực nghiệm (`log_gen1.ps1`) và mô phỏng truyền tải dữ liệu thực tế.

---

Kiến trúc nguồn log: 
- Splunk Enterprise
- Sysmon
- Suricata
