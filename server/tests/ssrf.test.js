const { isSafeIp } = require("../scanner");

describe("SSRF IP Address Protection", () => {
  test("Allows standard public IP addresses", () => {
    expect(isSafeIp("8.8.8.8")).toBe(true);
    expect(isSafeIp("142.250.190.46")).toBe(true);
    expect(isSafeIp("2607:f8b0:4005:805::200e")).toBe(true); // google IPv6
  });

  test("Blocks IPv4 loopback & local addresses", () => {
    expect(isSafeIp("127.0.0.1")).toBe(false);
    expect(isSafeIp("127.0.0.2")).toBe(false);
    expect(isSafeIp("127.255.255.255")).toBe(false);
    expect(isSafeIp("0.0.0.0")).toBe(false);
  });

  test("Blocks IPv6 loopback", () => {
    expect(isSafeIp("::1")).toBe(false);
    expect(isSafeIp("0:0:0:0:0:0:0:1")).toBe(false);
  });

  test("Blocks IPv4 Private Address Ranges", () => {
    // 10.0.0.0/8
    expect(isSafeIp("10.0.0.1")).toBe(false);
    expect(isSafeIp("10.255.8.1")).toBe(false);
    
    // 172.16.0.0/12
    expect(isSafeIp("172.16.0.1")).toBe(false);
    expect(isSafeIp("172.31.255.255")).toBe(false);
    
    // 192.168.0.0/16
    expect(isSafeIp("192.168.1.1")).toBe(false);
    expect(isSafeIp("192.168.254.254")).toBe(false);
  });

  test("Blocks IPv4 Link-Local (169.254.x.x)", () => {
    expect(isSafeIp("169.254.169.254")).toBe(false);
    expect(isSafeIp("169.254.0.1")).toBe(false);
  });

  test("Blocks IPv6 Unique Local & Link-Local Ranges", () => {
    expect(isSafeIp("fc00::1")).toBe(false);
    expect(isSafeIp("fdff::ffff")).toBe(false);
    expect(isSafeIp("fe80::1")).toBe(false);
  });

  test("Blocks IPv4-Mapped IPv6 Private & Loopback addresses", () => {
    // mapped loopback
    expect(isSafeIp("::ffff:127.0.0.1")).toBe(false);
    
    // mapped private IPs
    expect(isSafeIp("::ffff:10.0.0.1")).toBe(false);
    expect(isSafeIp("::ffff:192.168.1.1")).toBe(false);
    
    // mapped link local
    expect(isSafeIp("::ffff:169.254.169.254")).toBe(false);
  });

  test("Allows IPv4-Mapped IPv6 Public addresses", () => {
    expect(isSafeIp("::ffff:8.8.8.8")).toBe(true);
  });

  test("Handles unparseable/invalid strings gracefully by blocking them", () => {
    expect(isSafeIp("not-an-ip")).toBe(false);
    expect(isSafeIp("999.999.999.999")).toBe(false);
    expect(isSafeIp("")).toBe(false);
  });
});
