---
title: Data thief

---

## Data thief

Link challenge: [Data Thief - Cookie Arena](https://battle.cookiearena.org/challenges/digital-forensics/data-thief)

We got a notification that the administrative website (written in PHP) was attacked. Bad guys have exploited vulnerabilities and stolen data. We captured network packets during the monitoring process. Could you help us investigate and find stolen content?

The Hackativity

Check what all users have been up to with this Challenge recently.

- Sau khi ta giải nén file zip, ta sẽ nhận được file .pcap, mở bằng wireshark và bắt đầu theo dõi:
- Ta sẽ dùng chức năng export objects theo giao thức HTTP để xem các file hay message được truyền đi:
- Và ta sẽ thấy nhiều command khả nghi ở đây:

![image](https://hackmd.io/_uploads/BJqYLmhWZe.png)


- Ta thấy các command đó khả năng đã bị mã hóa bằng base64, lên cyberchef, decrypt từng lệnh
- Ở đây, ta phải chọn kiểu alphabet khác, kiểu mặc định sẽ không được. Sau khi tui dò ra thì kiểu ROT13 sẽ decrypt được ra plain text
![image](https://hackmd.io/_uploads/ryc5Lm3b-g.png)


- Tiếp tục decrypt các đoạn mã còn lại, và tuyệt zời ta đã giải mã được một bản rõ rất giá trị ở đây

![image](https://hackmd.io/_uploads/rJSsL73ZWx.png)


- File flag.txt đã được nén bằng password Co0ki3Ar3n4, bây giờ nhiệm vụ của ta là phải tìm được file flag.txt đó.
- Bước tiếp theo, ta có gợi ý là ICMP protocol, giờ dò lưu lượng mạng theo giao thức ICMP:
![image](https://hackmd.io/_uploads/H18hIX2-We.png)



- Ta bắt được gói tin có chứa tên file là flag.txt và kém theo nhiều ký tự kỳ lạ ⇒ đúng chỗ rồi -.-
- Tiếp theo ta xem data chứa nội dung về flag như thế nào:
![image](https://hackmd.io/_uploads/HJWaI7nZZl.png)



- Như nãy ta cũng vừa thấy file flag được nén bằng zip, và file zip hợp lệ nó phải bắt đầu bằng **`PK\x03\x04`** (Hex: `50 4B 03 04`).
- Như vậy ở đây, ta sẽ loại bỏ 2 byte đầu là 30 và 2c đi, thì mới có thể giải nén file zip được

( 30 (hex) ⇒ 0 (Ascii); 2c ⇒ , (Ascii) )

- Chưa dừng lại ở đó, khi ta tiếp tục xem các gói tin còn lại ta cũng sẽ nhận thấy mã hex của data nó tăng dần lần lượt là (31 2c), (32 2c), (33 2c), (34 2c).

![image](https://hackmd.io/_uploads/ryKVPXnWZx.png)


![image](https://hackmd.io/_uploads/SkESPm2Zbe.png)


![image](https://hackmd.io/_uploads/S1ZLwQ3Z-l.png)


![image](https://hackmd.io/_uploads/HJkvDXn-Wl.png)


- Như vậy, ta suy luận ra 1 điều là: các gói tin chứa từng phần (cụ thể là 5 phần của file flag.txt, nhiệm vụ của ta là cần phải ghép chúng lại với nhau thành 1 file zip, sau đó extract file zip này bằng passphrase (nãy ta tìm được ở trên).
- Tui đã tách hết 2 byte đầu của 5 data và sẽ được như sau:
1. `504b03040a0009000000cb434f5707993655280000001c00000008001c00666c61672e74787455540900031da32b651da32b`
2. `6575780b000104000000000400000000f2c67405caeb8e21c08cce49db2301f04b6d3bc1fc2518f5a46323a1e4ff413e5cfb`
3. `c00c1392438f504b070807993655280000001c000000504b01021e030a0009000000cb434f5707993655280000001c000000`
4. `080018000000000001000000a48100000000666c61672e74787455540500031da32b6575780b000104000000000400000000`
5. `504b050600000000010001004e0000007a0000000000`

⇒ Tiếp tục nối 5 data này thành một file zip bằng cách sau:
Sử dụng lệnh `xxd -r -p` để chuyển đổi chuỗi Hex đã nối thành file nhị phân `flag_recovered.zip`:

```python
# Chuỗi Hex đã nối 
full_hex="504b03040a0009000000cb434f5707993655280000001c00000008001c00666c61672e74787455540900031da32b651da32b6575780b000104000000000400000000f2c67405caeb8e21c08cce49db2301f04b6d3bc1fc2518f5a46323a1e4ff413e5cfbc00c1392438f504b070807993655280000001c000000504b01021e030a0009000000cb434f5707993655280000001c000000080018000000000001000000a48100000000666c61672e74787455540500031da32b6575780b000104000000000400000000504b050600000000010001004e0000007a0000000000"

# Chuyển đổi Hex sang Binary
echo "$full_hex" | xxd -r -p > flag_recovered.zip
```

![image](https://hackmd.io/_uploads/SJfxv73--l.png)


- Nhập passphrase =  Co0ki3Ar3n4, ta sẽ thu được file flag.txt
![image](https://hackmd.io/_uploads/Hyyzwm2--x.png)
