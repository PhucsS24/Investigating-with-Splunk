# Tryhackme: Investigating with Splunk

## I. Kịch bản
- SOC Analyst Johny đã quan sát thấy một số hành vi bất thường trong Logs của một số máy tính Windows. Có vẻ như adversary đã truy cập vào một số máy tính này và đã tạo thành công một số backdoor. Người quản lý của anh ấy đã yêu cầu anh ấy lấy các Logs đó từ các máy chủ bị nghi ngờ và nhập chúng vào Splunk để điều tra nhanh chóng.

- Nhiệm vụ: kiểm tra các Logs và xác định các bất thường.

---

## II. Trả lời câu hỏi:

### 1. Có bao nhiêu sự kiện đã được thu thập và đưa vào index main?
- **Answer**: `12256`
- **Giải thích**:
  - **Truy vấn**:
    ```
    index=main
    ```
    - Truy vấn liệt kê tất cả các sự kiện trong index `main`.
  - **Kết quả**:
    - Ta có thể thấy thông tin tất cả các sự kiện như ảnh bên dưới.
  ![Hình ảnh](https://github.com/PhucsS24/Investigating-with-Splunk/blob/main/images/cau1.png)

---

### 2. Trên một trong những host bị nhiễm, attacker đã tạo thành công một backdoor user. Tên user này là gì?
- **Answer**: `A1berto`
- **Giải thích**:
  - Đầu tiên, chúng ta cần biết Logs nào sẽ ghi lại các sự kiện khi một user mới được tạo ra? Vì chúng ta đang điều tra trong môi trường Windows thì Log liên quan sẽ là `Windows Security Logs` trong đó có các EventID.
  - **Vậy EventID nào sẽ ghi lại các sự kiện khi một user mới được tạo ra?** Đó là `EventID=4720`.
  - **Thực hiện truy vấn**:
    ```
    index=main EventID=4720
    ```
      - Truy vấn tìm kiếm các sự kiện khi một user mới được tạo ra với `EventID=4720`.
  - **Kết quả**:
    - Kiểm tra các sự kiện, ta thấy phần “New Account” có một “Account Name” là “A1berto”. 
    ![Hình ảnh](https://github.com/PhucsS24/Investigating-with-Splunk/blob/main/images/cau2.png)
    - Chúng ta có thể kiểm tra trong trường “SamAccountName” và thấy user “A1berto”.
    ![Hình ảnh](https://github.com/PhucsS24/Investigating-with-Splunk/blob/main/images/cau2.2.png)

---

### 3. Trên cùng một host, một registry key cũng được cập nhật liên quan backdoor user mới được tạo. Đường dẫn đầy đủ của registry key đó là gì?
- **Answer**: `HKLM\SAM\SAM\Domains\Account\Users\Names\A1berto\`
- **Giải thích**:
  - Câu hỏi đặt ra là **EventID nào sẽ ghi lại các sự kiện khi registry key thực hiện hành động cập nhật?** Đó là `EventID=13` ghi lại các sự kiện cập nhật registry key.
  - **Thực hiện truy vấn**:
    ```
    index = "main" EventID=13 A1berto
    ```
      - Truy vấn tìm kiếm các sự kiện cập nhật registry key với `EventID=13` khi user `A1berto` được tạo ra.
  - **Kết quả**:
    - Kiểm tra trong trường `TargetObject`, ta có thể thấy path đầy đủ của registry key là `HKLM\SAM\SAM\Domains\Account\Users\Names\A1berto\`.
      ![Hình ảnh](https://github.com/PhucsS24/Investigating-with-Splunk/blob/main/images/cau3.png)

---

### 4. Kiểm tra Logs và xác định user mà attacker đang cố gắng mạo danh?
- **Answer**: `Alberto`
- **Giải thích**:
  - Backdoor user mà attacker tạo ra là `A1berto`. Ta có thể thấy số `1` nhìn giống như chữ cái `L`. Nếu không nhìn kỹ, chúng ta có thể bị attacker đánh lừa đây là một user bình thường. Vậy khả năng cao attacker đang cố gắng mạo danh user “Alberto” trong hệ thống.
  - Để chứng minh điều đó, ta kiểm tra các User đã tồn tại trước đó:
    - **Truy vấn**: ```index = "main"```
    - Kiểm tra trong trường `User`, ta thấy có user `Cybertees\Alberto`. Vậy chắc chắn attacker đang mạo danh user `Alberto`.
  ![Hình ảnh](https://github.com/PhucsS24/Investigating-with-Splunk/blob/main/images/cau4.png)

---

### 5. Lệnh nào được sử dụng để thêm một backdoor user từ remote computer?
- **Answer**: `C:\windows\System32\Wbem\WMIC.exe" /node:WORKSTATION6 process call create "net user /add A1berto paw0rd1`
- **Giải thích**:
  - Attacker sử dụng lệnh để thêm một backdoor user từ xa, lệnh thực thi đó phải chạy một tiến trình tạo user trên Windows. Do đó, chúng ta cần biết EventID nào sẽ ghi lại các sự kiện tạo mới một tiến trình? Đó là `EventID=1` trong Sysmon và `EventID=6488` trong Windows Security Logs.
  - **Thực hiện truy vấn**:
    ```
    index="main" EventID=1 OR EventID=4688 A1berto
    ```
      - Truy vấn tìm kiếm các sự kiện khi có tiến trình mới được tạo liên quan đến user `A1berto`.
  - **Kết quả**:
    - Kiểm tra trong trường `CommandLine`, ta thấy các lệnh thực thi mà attacker đã sử dụng, trong đó lệnh tạo user mới là:
      ```
      "C:\windows\System32\Wbem\WMIC.exe" /node:WORKSTATION6 process call create "net user /add A1berto paw0rd1"
      ```
    - Ta thấy lệnh trên có sử dụng `wmic`, là command-line tool có thể được sử dụng để thực hiện lệnh từ xa.
  ![Hình ảnh](https://github.com/PhucsS24/Investigating-with-Splunk/blob/main/images/cau5.png)

---

### 6. Trong quá trình điều tra, backdoor user đã cố gắng đăng nhập bao nhiêu lần?
- **Answer**: `0`
- **Giải thích**:
  - Để kiểm tra backdoor user thực hiện đăng nhập bao nhiêu lần, bao gồm cả đăng nhập thành công và đăng nhập thất bại, ta cần biết các EventID tương ứng. `EventID=4624` ghi lại các sự kiện đăng nhập thành công, `EventID=4625` ghi lại các sự kiện đăng nhập thất bại.
  - **Thực hiện truy vấn**:
    ```
    index="main" EventID="4625" OR EventID="4624" A1berto
    ```
      - Truy vấn tìm kiếm các sự kiện user `A1berto` đăng nhập thất bại hoặc đăng nhập thành công.
  - **Kết quả**:
    - Kết quả cho thấy không có sự kiện đăng nhập nào của backdoor user `A1berto`.
  ![Hình ảnh](https://github.com/PhucsS24/Investigating-with-Splunk/blob/main/images/cau6.png)

---

### 7. Tên của host bị nhiễm, mà lệnh Powershell đáng ngờ được thực thi là gì?
- **Answer**: `James.browne`
- **Giải thích**:
  - Để biết được attacker đã thực thi lệnh Powershell trên những host nào, chúng ta cần biết EventID nào sẽ ghi lại các sự kiện khi lệnh Powershell được thực thi? Đó là `EventID=4104` ghi lại sự kiện các khối mã lệnh (script block) đã được thực thi và `EventID=4103` ghi lại các sự kiện thực thi chuỗi lệnh trong PowerShell.
  - **Thực hiện truy vấn**:
    ```
    index="main" EventID="4104" OR EventID="4103"
    ```
      - Truy vấn tìm kiếm các sự kiện thực thi lệnh Powershell.
  - **Kết quả**:
    - Kiểm tra trong trường `hostname`, ta thấy chỉ có hostname `James.browne` là nơi mà lệnh PowerShell được thực thi.
  ![Hình ảnh](https://github.com/PhucsS24/Investigating-with-Splunk/blob/main/images/cau7.png)

---

### 8. Logs PowerShell đã được bật trên thiết bị này. Có bao nhiêu sự kiện được ghi Logs cho việc thực thi PowerShell độc hại?
- **Answer**: `79`
- **Giải thích**:
  - Sử dụng lại truy vấn ở `câu 7`:
    ```
    index="main" EventID="4104" OR EventID="4103"
    ```
  - **Kết quả**:
    - Có `79` sự kiện được ghi lại cho việc thực thi PowerShell độc hại.
  ![Hình ảnh](https://github.com/PhucsS24/Investigating-with-Splunk/blob/main/images/cau8.png)

---

### 9. Một Powershell script được mã hóa từ host bị nhiễm đã khởi tạo một yêu cầu web. URL đầy đủ là gì?
- **Answer**: `hxxp[://]10[.]10[.]10[.]5/news[.]php`
- **Giải thích**:
  - Sau khi thực hiện truy vấn ```index="main" EventID="4104" OR EventID="4103"```, chúng ta đã phát hiện ra có `79` sự kiện thực thi Powershell. Ta cũng có thể kiểm tra trong trường “ContextInfo” và phát hiện các lệnh Powershell được mã hóa dạng base64.
    ![Hình ảnh](https://github.com/PhucsS24/Investigating-with-Splunk/blob/main/images/cau9.1.png)
    
  - Ngoài ra ta có thể thấy trong các sự kiện trong trường `ContextInfo` có `Host Application` là nơi lưu các giá trị các lệnh Powershel dạng encoded.
    ![Hình ảnh](https://github.com/PhucsS24/Investigating-with-Splunk/blob/main/images/cau9.2.png)
    
  - Tiếp theo, chúng ta thực hiện truy vấn lọc các giá trị Powershell dạng encoded:
      ```
      index="main" EventID="4104" OR EventID="4103" 
      |rex field=ContextInfo "Host Application = (?<Command>[^\r\n]+)" 
      | table Command 
      | dedup Command
      ```
      - Truy vấn trích xuất giá trị của `Host Application` từ trường `ContextInfo`, hiển thị trên bảng không trùng lặp.
        
    - **Kết quả**:
      - Ta thấy chỉ có một lệnh Powershell được mã hóa base64 duy nhất như hình bên dưới (dấu hiệu mã hóa base64 có tham số `-enc`).
      ![Hình ảnh](https://github.com/PhucsS24/Investigating-with-Splunk/blob/main/images/cau9.png)

      - Copy giá trị mã hóa và giải mã với tool `cyberchef`.
        ![Hình ảnh](https://github.com/PhucsS24/Investigating-with-Splunk/blob/main/images/cau9.3.png)
        
      - Sau khi giải mã ta thấy các tập lệnh Powershell đang cố gắng vô hiệu hóa cơ chế `ScriptBlock Logging` trong PowerShell. `“EnableScriptBlockLogging”` và `“EnableScriptBlockInvocationLogging”` được thiết lập giá trị bằng `0`. Điều này sẽ ngăn hệ thống ghi log các tập lệnh PowerShell được thực thi.
      - Ngoài ra ta còn thấy một chuỗi đang được mã hóa với base64 `aAB0AHQAcAA6AC8ALwAxADAALgAxADAALgAxADAALgA1AA==` và một đường dẫn hoặc thư mục `/new.php`. có thể chuỗi này là một URL đầy đủ dẫn đến một domain hoặc IP độc hại của attacker.
      - Tiếp tục giải mã chuỗi `aAB0AHQAcAA6AC8ALwAxADAALgAxADAALgAxADAALgA1AA==` với `cyberchef`.
        ![Hình ảnh](https://github.com/PhucsS24/Investigating-with-Splunk/blob/main/images/cau9.4.png)
      - Kết quả cho thấy đây là một đường dẫn đến webserver của attcker `hxxp[://]10[.]10[.]10[.]5` cùng với `/new.php` thì ta được một URL hoàn chỉnh là `hxxp[://]10[.]10[.]10[.]5/news[.]php`
        ![Hình ảnh](https://github.com/PhucsS24/Investigating-with-Splunk/blob/main/images/cau9.5.png)

---
