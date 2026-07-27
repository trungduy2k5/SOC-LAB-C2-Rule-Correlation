# SOC-LAB-C2-Rule-Correlation
# 🛡️ SIEM Detection Rules & Correlation Engine (Splunk + Sysmon + Suricata)

Đề tài xây dựng hệ thống **SIEM (Splunk Enterprise)** và các **Quy tắc Tương quan (Correlation Rules)** nâng cao nhằm phát hiện các hành vi tấn công mạng tinh vi, đặc biệt tập trung vào các giai đoạn **Kênh điều khiển C2 (Command & Control)**, **Chuyển dịch ngang (Lateral Movement)**, và **Đánh cắp dữ liệu (Data Exfiltration)**.

Hệ thống kết hợp kỹ thuật phòng thủ tương quan chéo (Cross-source Correlation) giữa log **hành vi tiến trình máy trạm (Windows Sysmon)** và **lưu lượng mạng (Suricata NIDS)**, đi kèm kịch bản sinh log thực nghiệm (`log_gen1.ps1`) và mô phỏng truyền tải dữ liệu thực tế.

---

Kiến trúc nguồn log: 
- Splunk Enterprise
- Sysmon
- Suricata

---
**Lưu ý: Các kịch bản thực nghiệm trong đề tài này được lý tưởng hóa, trong môi trường đã tắt các biện pháp bảo vệ. Mục tiêu của đề tài là phát triển và xây dựng các quy tắc tương quan
dựa trên phân tích hành vi, và thực hiện theo các Detection Method dựa trên Mitre Att&ck.

** Các kịch bản không phản ánh thực tế các cuộc tấn công hiện nay, đề tài dựa trên các hành vi cốt lõi để xây dựng các quy tắc, trình độ của sinh viên đại học, nhằm mục đích nghiên cứu và học tập.
** Repo này là 1 phần nhỏ trong đề tài được thực hiện riêng lẻ bởi 1 cá nhân.
** AT200217 - Nguyễn Trung Duy
