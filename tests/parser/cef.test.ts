import { describe, it, expect } from 'vitest';
import { parseCef } from '../../src/parser/cef.js';

const ADMIN_LOGIN_CEF =
  'CEF:0|Ubiquiti|UniFi Network|9.3.33|544|Admin Accessed UniFi Network|1|UNIFIcategory=System UNIFIsubCategory=Admin UNIFIhost=Office UDM Pro UNIFIaccessMethod=web UNIFIadmin=Craig src=105.5.138.59 msg=Craig accessed UniFi Network using the web. Source IP: 105.5.138.59';

const WIFI_DISCONNECT_CEF =
  'CEF:0|Ubiquiti|UniFi Network|9.3.33|401|WiFi Client Disconnected|2|UNIFIcategory=Monitoring UNIFIsubCategory=WiFi UNIFIhost=Office UDM Pro UNIFIlastConnectedToDeviceName=Lobby AP UNIFIlastConnectedToDeviceIp=192.168.100.5 UNIFIlastConnectedToDeviceMac=d8:b3:70:fb:fc:dd UNIFIlastConnectedToDeviceModel=U7-Pro UNIFIlastConnectedToDeviceVersion=8.0.9 UNIFIclientAlias=Apple Watch 0d:87 UNIFIclientHostname=Craig Watch UNIFIclientIp=192.168.10.178 UNIFIclientMac=0a:be:db:c8:0d:81 UNIFIwifiChannel=153 UNIFIwifiChannelWidth=20 UNIFIwifiName=Employee WiFi UNIFIwifiBand=na UNIFIwifiAirtimeUtilization=14 UNIFIwifiInterference=9 UNIFIlastConnectedToWiFiRssi=-77 UNIFIduration=6m 22s UNIFIusageDown=11.78 KB UNIFIusageUp=4.46 KB UNIFInetworkName=Employee Network UNIFInetworkSubnet=192.168.10.0/24 UNIFInetworkVlan=10 msg=Apple Watch 0d:87 disconnected from Employee WiFi. Time Connected: 6m 22s. Data Used: 4.46 KB (up) / 11.78 KB (down). Last Connected To: Lobby AP at -77 dBm.';

describe('parseCef', () => {
  it('parses the documented admin-login example', () => {
    const result = parseCef(ADMIN_LOGIN_CEF);
    expect(result).not.toBeNull();
    expect(result?.version).toBe('0');
    expect(result?.vendor).toBe('Ubiquiti');
    expect(result?.product).toBe('UniFi Network');
    expect(result?.deviceVersion).toBe('9.3.33');
    expect(result?.signatureId).toBe('544');
    expect(result?.name).toBe('Admin Accessed UniFi Network');
    expect(result?.severity).toBe('1');
    expect(result?.extension.UNIFIcategory).toBe('System');
    expect(result?.extension.UNIFIsubCategory).toBe('Admin');
    expect(result?.extension.UNIFIadmin).toBe('Craig');
    expect(result?.extension.src).toBe('105.5.138.59');
    expect(result?.extension.msg).toBe(
      'Craig accessed UniFi Network using the web. Source IP: 105.5.138.59'
    );
  });

  it('parses the documented WiFi-disconnect example, including multi-word values', () => {
    const result = parseCef(WIFI_DISCONNECT_CEF);
    expect(result).not.toBeNull();
    expect(result?.name).toBe('WiFi Client Disconnected');
    expect(result?.severity).toBe('2');
    expect(result?.extension.UNIFIhost).toBe('Office UDM Pro');
    expect(result?.extension.UNIFIlastConnectedToDeviceIp).toBe('192.168.100.5');
    expect(result?.extension.UNIFIclientIp).toBe('192.168.10.178');
    expect(result?.extension.UNIFIwifiName).toBe('Employee WiFi');
    expect(result?.extension.UNIFInetworkSubnet).toBe('192.168.10.0/24');
    expect(result?.extension.msg).toContain('disconnected from Employee WiFi');
  });

  it('unescapes backslash-escaped pipes and backslashes in header fields', () => {
    const raw = 'CEF:0|Vendor\\|Sub|Product|1.0|1|Name|5|msg=hello';
    const result = parseCef(raw);
    expect(result?.vendor).toBe('Vendor|Sub');
  });

  it('unescapes backslash-escaped equals signs in extension values', () => {
    const raw = 'CEF:0|Vendor|Product|1.0|1|Name|5|msg=a\\=b';
    const result = parseCef(raw);
    expect(result?.extension.msg).toBe('a=b');
  });

  it('returns null for a payload missing the CEF: prefix', () => {
    expect(parseCef('not a cef payload')).toBeNull();
  });

  it('returns null for a truncated header with fewer than 7 fields', () => {
    expect(parseCef('CEF:0|Ubiquiti|UniFi Network|9.3.33')).toBeNull();
  });

  it('returns null for an empty string', () => {
    expect(parseCef('')).toBeNull();
  });
});
