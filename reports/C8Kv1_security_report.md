# C8Kv1 安全漏洞报告

- **设备型号**: C8000V
- **系统版本**: IOS-XE 17.14.01a123123
- **检测时间**: 2025-07-31
- **安全公告总数**: 17

---

## 漏洞详情

1. **[Cisco Adaptive Security Appliance Software, Firepower Threat Defense Software, IOS Software, and IOS XE Software IKEv2 Denial of Service Vulnerability](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-multiprod-ikev2-dos-gPctUqv2)**
   - 危害等级: High
   - CVSS分数: 8.6
   - CVE编号: CVE-2025-20182
   - 修复版本: 17.15.1
   - 简要描述: IKEv2协议处理存在DoS漏洞，攻击者可导致服务中断。

2. **[Cisco IOS and IOS XE Software SNMPv3 Configuration Restriction Vulnerability](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-snmpv3-qKEYvzsy)**
   - 危害等级: Medium
   - CVSS分数: 4.3
   - CVE编号: CVE-2025-20151
   - 修复版本: 17.15.1z, 17.15.3
   - 简要描述: SNMPv3配置限制不当，认证远程攻击者可利用。

3. **[Cisco IOS XE SD-WAN Software Packet Filtering Bypass Vulnerability](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-snmp-bypass-HHUVujdn)**
   - 危害等级: Medium
   - CVSS分数: 5.3
   - CVE编号: CVE-2025-20221
   - 修复版本: 17.15.3, 17.15.1y
   - 简要描述: SD-WAN包过滤可被绕过，导致流量未被正确过滤。

4. **[Cisco IOS XE Software Bootstrap Arbitrary File Write Vulnerability](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-bootstrap-KfgxYgdh)**
   - 危害等级: Medium
   - CVSS分数: 6.0
   - CVE编号: CVE-2025-20155
   - 修复版本: 17.15.1
   - 简要描述: Bootstrap加载过程可被本地攻击者写入任意文件。

5. **[Cisco IOS XE Software DHCP Snooping Denial of Service Vulnerability](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-dhcpsn-dos-xBn8Mtks)**
   - 危害等级: High
   - CVSS分数: 8.6
   - CVE编号: CVE-2025-20162
   - 修复版本: 17.15.2, 17.15.1b
   - 简要描述: DHCP Snooping功能可被远程攻击者导致接口队列阻塞。

6. **[Cisco IOS XE Software for WLC Wireless IPv6 Clients Denial of Service Vulnerability](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-wlc-wncd-p6Gvt6HL)**
   - 危害等级: High
   - CVSS分数: 7.4
   - CVE编号: CVE-2025-20140
   - 修复版本: 17.15.1
   - 简要描述: WLC无线IPv6客户端可被攻击导致DoS。

7. **[Cisco IOS XE Software Internet Key Exchange Version 1 Denial of Service Vulnerability](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-ikev1-dos-XHk3HzFC)**
   - 危害等级: High
   - CVSS分数: 7.7
   - CVE编号: CVE-2025-20192
   - 修复版本: 17.15.1
   - 简要描述: IKEv1实现可被远程攻击导致DoS。

8. **[Cisco IOS XE Software Privilege Escalation Vulnerabilities](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-privesc-su7scvdp)**
   - 危害等级: High
   - CVSS分数: 6.7
   - CVE编号: CVE-2025-20197, CVE-2025-20198, CVE-2025-20199, CVE-2025-20200, CVE-2025-20201
   - 修复版本: 17.15.2, 17.15.1x
   - 简要描述: CLI本地高权限用户可提权至root。

9. **[Cisco IOS XE Software Web-Based Management Interface Command Injection Vulnerability](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-webui-cmdinj-gVn3OKNC)**
   - 危害等级: High
   - CVSS分数: 8.8
   - CVE编号: CVE-2025-20186
   - 修复版本: 17.15.1
   - 简要描述: Web管理界面命令注入，远程攻击者可利用。

10. **[Cisco IOS XE Software Web-Based Management Interface Vulnerabilities](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-webui-multi-ARNHM4v6)**
    - 危害等级: Medium
    - CVSS分数: 6.5
    - CVE编号: CVE-2025-20193, CVE-2025-20194, CVE-2025-20195
    - 修复版本: 17.15.2, 17.15.1x
    - 简要描述: Web管理界面存在多个信息泄露和越权漏洞。

11. **[Cisco IOS XE Wireless Controller Software Cisco Discovery Protocol Denial of Service Vulnerability](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ewlc-cdp-dos-fpeks9K)**
    - 危害等级: High
    - CVSS分数: 7.4
    - CVE编号: CVE-2025-20202
    - 修复版本: 17.15.2, 17.15.1x
    - 简要描述: CDP协议处理可导致DoS。

12. **[Cisco IOS, IOS XE, and IOS XR Software TWAMP Denial of Service Vulnerability](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-twamp-kV4FHugn)**
    - 危害等级: High
    - CVSS分数: 8.6
    - CVE编号: CVE-2025-20154
    - 修复版本: 17.15.2, 17.15.1x
    - 简要描述: TWAMP协议处理可导致远程DoS。

13. **[Cisco IOx Application Hosting Environment Denial of Service Vulnerability](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iox-dos-95Fqnf7b)**
    - 危害等级: Medium
    - CVSS分数: 5.3
    - CVE编号: CVE-2025-20196
    - 修复版本: 17.15.3
    - 简要描述: IOx应用托管环境可被远程攻击导致DoS。

14. **[Cisco IOS, IOS XE, and IOS XR Software SNMP Denial of Service Vulnerabilities](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-snmp-dos-sdxnSUcW)**
    - 危害等级: High
    - CVSS分数: 7.7
    - CVE编号: CVE-2025-20169, CVE-2025-20170, CVE-2025-20171, CVE-2025-20172, CVE-2025-20173, CVE-2025-20174, CVE-2025-20175, CVE-2025-20176
    - 修复版本: 17.15.3, 17.15.1y
    - 简要描述: SNMP子系统存在多个DoS漏洞。

15. **[Cisco IOS and IOS XE Software Resource Reservation Protocol Denial of Service Vulnerability](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-rsvp-dos-OypvgVZf)**
    - 危害等级: High
    - CVSS分数: 8.6
    - CVE编号: CVE-2024-20433
    - 修复版本: 17.15.1
    - 简要描述: RSVP协议处理可导致远程DoS。

16. **[Cisco IOS XE Software SD-Access Fabric Edge Node Denial of Service Vulnerability](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ios-xe-sda-edge-dos-MBcbG9k)**
    - 危害等级: High
    - CVSS分数: 8.6
    - CVE编号: CVE-2024-20480
    - 修复版本: 17.15.1
    - 简要描述: SD-Access边缘节点DHCP Snooping功能可导致高CPU利用率。

17. **[Cisco IOS XE Software Easy Virtual Switching System Arbitrary Code Execution Vulnerability](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ios-xe-evss-code-exe-8cw5VSvw)**
    - 危害等级: High
    - CVSS分数: 8.1
    - CVE编号: CVE-2021-1451
    - 修复版本: 17.15.1
    - 简要描述: VSS功能存在任意代码执行漏洞。

---

> 建议尽快升级至官方推荐的修复版本，详情请参考每条漏洞的Cisco官方公告链接。
