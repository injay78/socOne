# Xử lý lỗi kết nối tới hệ thống nội bộ SHB

Runbook cho các ứng dụng Python chạy trên máy trong mạng SHB (bao gồm VM). Ba
nguyên nhân dưới đây biểu hiện rất giống nhau — đều ra "connection reset",
"timeout" hoặc "SSL error" — nhưng cách sửa hoàn toàn khác. Phân biệt trước,
sửa sau.

## Phân biệt ba nguyên nhân

Chạy đúng thứ tự này, dừng ở bước đầu tiên fail:

```python
import socket, ssl

HOST, PORT = "10.4.27.7", 443

# 1. TCP có thông không?
s = socket.create_connection((HOST, PORT), timeout=8)
print("TCP OK, source =", s.getsockname()[0]); s.close()

# 2. TLS bắt tay được không (bỏ qua xác thực)?
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
with socket.create_connection((HOST, PORT), timeout=8) as r:
    with ctx.wrap_socket(r, server_hostname=HOST) as t:
        print("TLS OK:", t.version())

# 3. Cert có được tin cậy không?
import httpx
print(httpx.get(f"https://{HOST}/", timeout=10).status_code)
```

| Bước fail | Nguyên nhân | Sửa ở mục |
| --- | --- | --- |
| 1 — TCP timeout | Sai route (traffic nội bộ đi ra Wi-Fi) | A |
| 1 — `getaddrinfo failed` / NXDOMAIN | Sai tên miền hoặc sai DNS | C |
| 3 — `CERTIFICATE_VERIFY_FAILED` | TLS inspection / cert nội bộ | B |

Mẹo phân biệt nhanh nguyên nhân A: nếu socket **bind vào IP của card nội bộ**
thì thông, còn không bind thì timeout, chắc chắn là lỗi route.

```python
s = socket.socket(); s.bind(("10.8.4.33", 0))   # IP của Ethernet nội bộ
s.settimeout(7); s.connect(("10.4.27.7", 443))  # thông => lỗi route
```

## A. Sai route trên máy multi-homed

Máy có hai đường: Ethernet nội bộ và Wi-Fi (SHB-GUEST). Wi-Fi thắng default
route, còn Ethernet chỉ có route on-link cho đúng subnet của nó. Mọi địa chỉ
nội bộ **ngoài** subnet đó bị đẩy ra Wi-Fi và timeout.

Kiểm tra — metric hiệu dụng thấp nhất là đường thắng:

```powershell
Get-NetRoute -DestinationPrefix '0.0.0.0/0' |
  Select-Object InterfaceAlias, NextHop,
                @{n='Effective';e={$_.RouteMetric + $_.InterfaceMetric}} |
  Sort-Object Effective
```

Sửa — thêm route bền vững cho toàn dải nội bộ, chạy PowerShell **as
Administrator**:

```powershell
route -p add 10.0.0.0 mask 255.0.0.0 10.8.4.1 metric 1 if <ifIndex-cua-Ethernet>
```

Lấy `ifIndex` bằng `Get-NetAdapter`. Internet vẫn đi Wi-Fi, nên **không dính
TLS inspection**; chỉ traffic nội bộ đi Ethernet.

Không dùng `New-NetRoute -PolicyStore PersistentStore` — nó fail với
`Windows System Error 87` trên nền tảng này. `route -p` ghi đồng thời vào bảng
đang chạy và persistent store.

Trong repo socOne có sẵn script làm việc này kèm bước tự kiểm chứng:
`deploy/native/setup-internal-route.ps1`.

## B. TLS inspection và cert nội bộ

Đường nội bộ ký lại cert công cộng bằng `CN=SHB-CA, DC=shbho, DC=shb, DC=vn`.
Windows tin CA này (trình duyệt chạy tốt) nhưng **Python xác thực bằng
`certifi`**, nên mọi HTTPS từ Python fail với `CERTIFICATE_VERIFY_FAILED:
self-signed certificate in certificate chain`. Thiết bị nội bộ (ePO, QRadar)
thì dùng CA riêng của chúng, cũng không có trong `certifi`.

Cách đúng là dựng một CA bundle gộp thay vì tắt xác thực. Xuất CA từ Windows:

```powershell
$out = "C:\path\to\certs"
foreach ($t in @('6B2B1EFC72A7AB744A6AE42312ED636E973A4305')) {   # SHB-CA
  $c = Get-ChildItem Cert:\LocalMachine\Root | Where-Object Thumbprint -eq $t
  $b64 = [Convert]::ToBase64String($c.RawData,'InsertLineBreaks')
  "-----BEGIN CERTIFICATE-----`n$b64`n-----END CERTIFICATE-----" |
    Add-Content "$out\corporate-ca.pem" -Encoding ascii
}
```

Lấy cert của một thiết bị nội bộ không có trong store (ví dụ ePO):

```python
import socket, ssl
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
with socket.create_connection(("10.4.29.50", 8443), timeout=8) as r:
    with ctx.wrap_socket(r, server_hostname="10.4.29.50") as t:
        der = t.getpeercert(binary_form=True)
open("epo.pem", "w").write(ssl.DER_cert_to_PEM_cert(der))
```

Gộp lại rồi trỏ Python vào:

```bash
cat "$(python -c 'import certifi;print(certifi.where())')" corporate-ca.pem epo.pem > ca-bundle.pem
```

```dotenv
SSL_CERT_FILE=C:\path\to\certs\ca-bundle.pem
REQUESTS_CA_BUNDLE=C:\path\to\certs\ca-bundle.pem
```

`SSL_CERT_FILE` áp cho `ssl`/`httpx`; `REQUESTS_CA_BUNDLE` áp cho `requests`.
Đặt cả hai. Nhớ dựng lại bundle mỗi khi cert được gia hạn.

Nếu thiết bị chỉ gửi leaf cert mà không gửi CA (QRadar là ví dụ), bỏ thẳng leaf
đó vào bundle cũng chạy — nhưng phải làm lại khi cert hết hạn.

## C. Sai tên miền

Trước khi nghi ngờ mạng, kiểm tra tên có tồn tại không. DNS nội bộ
(`10.4.82.20`, `10.18.82.22`) phân giải được **cả tên nội bộ lẫn tên công
cộng**, nên nếu nó trả NXDOMAIN thì tên đó thật sự sai:

```powershell
nslookup <hostname> 10.4.82.20
```

## Áp dụng cho dlpAuto

Đã kiểm tra ngày 2026-08-19:

- **Cả hai đích đều là lỗi nguyên nhân A (sai route).** `mail.shb.com.vn` phân
  giải ra `10.4.82.15`, còn ePO là `10.4.29.50` — cả hai đều nằm ngoài subnet
  on-link `10.8.4.0/24`, nên trước khi có route `10.0.0.0/8` chúng bị đẩy ra
  Wi-Fi và timeout.
- Sau khi thêm route, socket **không bind** đã kết nối được qua `10.8.4.33`:
  `mail.shb.com.vn:443` OK, `10.4.29.50:8443` OK. Route áp ở mức máy nên dlpAuto
  hưởng luôn, **không phải sửa code hay sửa `.env`**.
- `EXCHANGE_SERVER=mail.shb.com.vn` trong `.env` đã đúng. (Lưu ý khi tra cứu:
  `mai.shb.com.vn` — thiếu chữ `l` — trả NXDOMAIN, dễ gây chẩn đoán nhầm thành
  lỗi tên miền.)
- `mail.shb.com.vn:25` bị `ConnectionRefused`, nhưng không sao: dlpAuto dùng
  `exchangelib` qua EWS trên cổng 443, không dùng SMTP cổng 25.
- dlpAuto hiện dùng `requests` với `verify=False` ở khắp nơi
  (`dlpUpdate.py`, `getManager.py`, `mailLib.py`, `trellixApi.py`), nên **không
  dính nguyên nhân B**. Đổi lại là mất khả năng phát hiện MITM. Khi có điều
  kiện thì chuyển sang `REQUESTS_CA_BUNDLE` theo mục B và bỏ `verify=False`.
- Cert của ePO: `CN=DC-ePO-Master, OU=Orion, O=McAfee`, tự ký bởi
  `Orion_CA_DC-ePO-Master`, **không có SAN**. Vì thiếu SAN nên khi bật xác thực
  phải dùng `verify=<đường-dẫn-pem>` kèm tắt hostname check, hoặc cấp lại cert
  có SAN chứa `10.4.29.50`.
