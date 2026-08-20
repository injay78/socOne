# Chia sẻ mạng nội bộ SHB qua Tailscale

Biến máy này thành **subnet router** để các máy khác trong tailnet truy cập
được hệ thống nội bộ SHB (QRadar, ePO, Exchange, DNS nội bộ) mà không cần ngồi
trong mạng SHB.

Điều kiện tiên quyết: route nội bộ đã hoạt động — xem
[`setup-internal-route.ps1`](setup-internal-route.ps1) và
[`corporate-network-troubleshooting.md`](corporate-network-troubleshooting.md).
Nếu chính máy này chưa kết nối được `10.4.27.7` thì subnet router cũng vô nghĩa.

## Subnet router hay exit node?

Hai thứ khác nhau, hay bị gọi nhầm:

| | Subnet router | Exit node |
| --- | --- | --- |
| Cờ | `--advertise-routes=<CIDR>` | `--advertise-exit-node` |
| Máy remote gửi gì qua đây | Chỉ traffic tới đúng các CIDR được advertise | **Toàn bộ** traffic, kể cả internet |
| Đường ra | Ethernet0 → `10.8.4.1` | Default route → Wi-Fi SHB-GUEST |

**Để truy cập mạng nội bộ thì dùng subnet router.** Exit node chỉ cần khi muốn
máy remote đi internet bằng đường mạng của máy này — kéo theo việc dính chính
sách và TLS inspection của SHB-GUEST, và tốn băng thông của máy này. Mục 8 mô
tả cách bật thêm nếu thực sự cần.

## Hiện trạng máy này

Kiểm tra ngày 2026-08-20:

- Tailscale 1.94.2, `BackendState: Running`, node `DESKTOP-8IBJCH8` = `100.121.235.53`
- Ethernet0 `10.8.4.33/24` (nội bộ), Wi-Fi `172.16.51.145/22` (internet, giữ default route)
- Route bền vững `10.0.0.0/8 → 10.8.4.1` qua Ethernet0 đã có, metric 1
- **Chưa advertise route nào**, và **IP forwarding đang tắt** (`IPEnableRouter=0`,
  `Forwarding: Disabled` trên cả Ethernet0/Wi-Fi/Tailscale)

Nghĩa là chỉ còn thiếu mục 1–4 dưới đây.

## 1. Chọn dải cần chia sẻ

Đừng advertise `10.0.0.0/8`. Nó nuốt trọn mọi địa chỉ 10.x trên máy remote,
nên máy nào có LAN nhà/văn phòng nằm trong 10.x sẽ **mất mạng nội bộ của chính
nó** khi bật route. Advertise đúng dải cần dùng:

```
10.4.0.0/16      # QRadar 10.4.27.7, ePO 10.4.29.50, Exchange 10.4.82.15, DNS 10.4.82.20
10.8.4.0/24      # subnet on-link của Ethernet0
10.18.82.0/24    # DNS phụ 10.18.82.22
```

Cần thêm hệ thống khác thì bổ sung CIDR tương ứng, đừng nới rộng thành /8.

## 2. Bật IP forwarding trên Windows

Không có bước này, Tailscale vẫn báo advertise route thành công nhưng gói tin
tới rồi bị **drop im lặng** — triệu chứng y hệt firewall chặn. Chạy PowerShell
**as Administrator**:

```powershell
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -Name IPEnableRouter -Value 1 -Type DWord
Set-Service RemoteAccess -StartupType Automatic
Start-Service RemoteAccess
Set-NetIPInterface -InterfaceAlias Tailscale -AddressFamily IPv4 -Forwarding Enabled
Set-NetIPInterface -InterfaceAlias Ethernet0 -AddressFamily IPv4 -Forwarding Enabled
```

`IPEnableRouter` chỉ có hiệu lực sau khi service `RemoteAccess` chạy hoặc sau
khi reboot — start service là cách tránh reboot.

Kiểm tra:

```powershell
Get-NetIPInterface -AddressFamily IPv4 | Where-Object InterfaceAlias -in 'Ethernet0','Tailscale' | Select-Object InterfaceAlias, Forwarding
```

Lưu ý: interface `Tailscale` được tạo lại mỗi lần service Tailscale khởi động,
nên cờ `Forwarding` trên nó có thể bị reset. Nếu sau khi reboot mà route ngừng
hoạt động, chạy lại đúng dòng `Set-NetIPInterface -InterfaceAlias Tailscale`.

## 3. Advertise route

PowerShell **as Administrator**:

```powershell
& 'C:\Program Files\Tailscale\tailscale.exe' set --advertise-routes=10.4.0.0/16,10.8.4.0/24,10.18.82.0/24
```

Dùng `tailscale set`, không dùng `tailscale up` — `set` sửa preference tại chỗ,
không bắt đăng nhập lại và không xoá mất các cờ khác.

Giữ nguyên mặc định `--snat-subnet-routes=true`: máy nội bộ sẽ thấy traffic đến
từ `10.8.4.33` nên định tuyến chiều về hoạt động ngay. Nếu tắt SNAT, router lõi
của SHB phải biết đường về dải `100.64.0.0/10` — **không làm việc này**.

Xác nhận preference đã ghi:

```powershell
& 'C:\Program Files\Tailscale\tailscale.exe' status --json | ConvertFrom-Json | Select-Object -ExpandProperty Self | Select-Object HostName, AllowedIPs, PrimaryRoutes
```

## 4. Duyệt route trên admin console

Route **không hoạt động cho tới khi được duyệt**, kể cả khi máy này đã advertise
thành công. Đây là bước hay bị bỏ sót nhất.

Vào <https://login.tailscale.com/admin/machines> → chọn `DESKTOP-8IBJCH8` →
menu `...` → **Edit route settings** → tick từng subnet → Save.

Ngay tại đó làm luôn hai việc:

- **Disable key expiry** — mặc định key hết hạn sau 180 ngày, node rơi khỏi
  tailnet và route chết theo. Subnet router phải tắt hết hạn key.
- Gắn tag (ví dụ `tag:shb-subnet-router`) để viết ACL ở mục 9.

## 5. Chạy không cần đăng nhập

Mặc định Tailscale trên Windows dừng phục vụ khi user log out. Mở Tailscale từ
system tray → **Preferences** → bật **Run unattended**. Không có bước này thì
máy remote mất kết nối mỗi khi máy này khoá màn hình / log out.

## 6. Split DNS cho tên nội bộ

Route mở được IP nhưng chưa giải quyết được tên. Để máy remote resolve
`mail.shb.com.vn`, vào <https://login.tailscale.com/admin/dns>:

- **Nameservers** → **Add nameserver** → **Custom** → `10.4.82.20`
- Bật **Restrict to search domain**, thêm `shb.com.vn` và `shbho.shb.vn`
- Có thể thêm `10.18.82.22` làm nameserver dự phòng cho cùng domain

DNS nội bộ chỉ đến được khi dải `10.4.0.0/16` đã được duyệt ở mục 4 — làm mục 4
trước, nếu không toàn bộ DNS của máy remote sẽ treo theo.

Chỉ giới hạn theo search domain, **đừng** đặt `10.4.82.20` làm global
nameserver: mọi truy vấn internet của máy remote sẽ đi qua DNS SHB.

## 7. Bật ở phía máy remote

Route được advertise không tự động dùng — từng máy phải chấp nhận:

```powershell
tailscale set --accept-routes
```

```bash
sudo tailscale set --accept-routes
```

macOS/iOS/Android: bật trong app. Windows GUI: **Preferences → Use Tailscale
subnets**.

Kiểm chứng từ máy remote:

```powershell
tailscale status
```

```powershell
tailscale ping DESKTOP-8IBJCH8
```

```powershell
Test-NetConnection 10.4.27.7 -Port 443
```

```powershell
Resolve-DnsName mail.shb.com.vn
```

`tailscale ping` thông nhưng `Test-NetConnection` fail ⇒ lỗi nằm ở forwarding
(mục 2) hoặc route chưa duyệt (mục 4), không phải lỗi Tailscale.

Lưu ý cert: máy remote đi qua đường này vẫn gặp nguyên nhân B trong
`corporate-network-troubleshooting.md` (CA nội bộ ký lại cert, ePO không có
SAN). Route không sửa được chuyện đó — vẫn phải dựng CA bundle.

## 8. (Tuỳ chọn) Exit node

Chỉ bật khi muốn máy remote **đi internet** qua đây:

```powershell
& 'C:\Program Files\Tailscale\tailscale.exe' set --advertise-exit-node
```

Rồi duyệt trong admin console (cùng chỗ với route), và phía máy remote:

```powershell
tailscale set --exit-node=DESKTOP-8IBJCH8
```

```powershell
tailscale set --exit-node=
```

Cân nhắc trước khi bật:

- Traffic ra internet đi theo default route = **Wi-Fi SHB-GUEST**, nên dính
  đúng TLS inspection mà `setup-internal-route.ps1` đang cố tránh.
- Toàn bộ băng thông internet của máy remote đè lên đường Wi-Fi này.
- Máy remote dùng exit node **vẫn** cần `--accept-routes` để vào mạng nội bộ;
  exit node không thay thế subnet router.

## 9. ACL — giới hạn ai được dùng

Tailnet dùng ACL mặc định (`"dst": ["*:*"]`) thì **mọi thành viên** đều vào được
mạng nội bộ SHB ngay khi route được duyệt. Siết lại trong
<https://login.tailscale.com/admin/acls>:

```jsonc
{
  "tagOwners": { "tag:shb-subnet-router": ["autogroup:admin"] },
  "acls": [
    {
      "action": "accept",
      "src":    ["autogroup:member"],
      "dst":    ["10.4.0.0/16:443,8443", "10.8.4.0/24:*", "10.18.82.0/24:53"]
    }
  ]
}
```

Chỉnh `src` thành nhóm/user cụ thể nếu tailnet có nhiều người.

## 10. Gỡ bỏ

```powershell
& 'C:\Program Files\Tailscale\tailscale.exe' set --advertise-routes=
& 'C:\Program Files\Tailscale\tailscale.exe' set --advertise-exit-node=false
Set-NetIPInterface -InterfaceAlias Tailscale -AddressFamily IPv4 -Forwarding Disabled
Set-NetIPInterface -InterfaceAlias Ethernet0 -AddressFamily IPv4 -Forwarding Disabled
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -Name IPEnableRouter -Value 0 -Type DWord
Stop-Service RemoteAccess
Set-Service RemoteAccess -StartupType Disabled
```

Route `10.0.0.0/8` của bản thân máy này thì gỡ bằng
`.\setup-internal-route.ps1 -Remove`.

## 11. Chẩn đoán nhanh

| Triệu chứng | Nguyên nhân thường gặp |
| --- | --- |
| `tailscale status` ở máy remote không thấy subnet | Route chưa duyệt trong admin console (mục 4) |
| Thấy subnet nhưng mọi kết nối timeout | IP forwarding chưa bật (mục 2) |
| Chạy được, reboot xong hỏng | Cờ `Forwarding` trên interface Tailscale bị reset (mục 2) |
| Mất kết nối khi máy này log out / khoá màn hình | Chưa bật Run unattended (mục 5) |
| Hỏng sau vài tháng | Key của node hết hạn (mục 4) |
| IP thì thông, tên miền thì không | Chưa cấu hình split DNS (mục 6) |
| Máy remote mất LAN của chính nó | Đã advertise `10.0.0.0/8` — thu hẹp lại (mục 1) |
| TCP/TLS thông nhưng `CERTIFICATE_VERIFY_FAILED` | Nguyên nhân B trong `corporate-network-troubleshooting.md` |

## Lưu ý bảo mật

Cấu hình này mở một đường vào mạng nội bộ SHB cho mọi thiết bị trong tailnet,
đi vòng qua kiểm soát biên. Trước khi bật ở môi trường thật cần: xin phê duyệt
của IT/bảo mật SHB, siết ACL theo mục 9, bật device approval cho tailnet, và rà
lại danh sách thiết bị đang có trong tailnet.
