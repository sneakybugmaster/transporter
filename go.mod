module github.com/sneakybugmaster/transporter

go 1.26.0

tool (
	connectrpc.com/connect/cmd/protoc-gen-connect-go
	google.golang.org/protobuf/cmd/protoc-gen-go
)

require (
	connectrpc.com/connect v1.21.1
	github.com/coder/websocket v1.8.15
	github.com/vishvananda/netlink v1.3.1
	golang.org/x/crypto v0.58.0
	golang.org/x/time v0.16.0
	golang.zx2c4.com/wireguard v0.0.0-20261006164505-2631ce99a06f
	google.golang.org/protobuf v1.36.12
	modernc.org/sqlite v1.60.1
)

require (
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/mattn/go-isatty v0.0.24 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/vishvananda/netns v0.0.5 // indirect
	golang.org/x/net v0.60.0 // indirect
	golang.org/x/sys v0.49.0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
	modernc.org/libc v1.77.1 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.12.1 // indirect
)
