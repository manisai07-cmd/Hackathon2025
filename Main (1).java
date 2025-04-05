import java.io.*;
import java.text.SimpleDateFormat;
import java.util.*;

class Main {

    public static void main(String[] args) {
        Map<String, String> systemInfo = collectSystemInfo();
        Map<String, String> networkInfo = collectNetworkInfo();

        String timestamp = new SimpleDateFormat("yyyyMMdd_HHmmss").format(new Date());
        String reportPath = "Windows_Scan_Report_" + timestamp + ".txt";

        generateTextReport(systemInfo, networkInfo, reportPath);
        System.out.println("\nScan completed. Report saved to: " + reportPath);
    }

    public static Map<String, String> collectSystemInfo() {
        Map<String, String> info = new LinkedHashMap<>();
        info.put("OS Version", runPowerShell("(Get-CimInstance Win32_OperatingSystem).Caption"));
        info.put(".NET Versions", runPowerShell("Get-ChildItem 'HKLM:\\SOFTWARE\\Microsoft\\NET Framework Setup\\NDP' -Recurse | Get-ItemProperty -Name Version -EA 0 | Where { $_.PSChildName -match '^(?!S)' } | Select PSChildName, Version | Format-Table -HideTableHeaders"));
        info.put("AMSI Providers", runPowerShell("Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\AMSI\\Providers | Format-List"));
        info.put("Registered Antivirus", runPowerShell("Get-CimInstance -Namespace root\\SecurityCenter2 -ClassName AntiVirusProduct | Select displayName, pathToSignedProductExe"));
        info.put("Audit Policy", runPowerShell("auditpol /get /category:*"));
        info.put("Auto-run Programs", runPowerShell("Get-ItemProperty -Path 'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run'"));
        info.put("Firewall Rules", runPowerShell("Get-NetFirewallRule | Select DisplayName, Enabled, Direction, Action | Format-Table -HideTableHeaders"));
        info.put("Defender Settings", runPowerShell("Get-MpPreference | Select-Object -Property *"));
        info.put("Env Variables", runPowerShell("Get-ChildItem Env: | Format-Table Key,Value -HideTableHeaders"));
        info.put("User Downloads/Documents/Desktop", runPowerShell("Get-ChildItem -Path $env:USERPROFILE\\Downloads, $env:USERPROFILE\\Documents, $env:USERPROFILE\\Desktop"));
        info.put("Installed Hotfixes", runPowerShell("Get-HotFix | Select HotFixID, InstalledOn"));
        info.put("Installed Products", runPowerShell("Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | Select DisplayName, InstallDate"));
        info.put("Local Group Policy", runPowerShell("secedit /export /cfg temp.inf && type temp.inf"));
        info.put("Non-empty Local Groups", runPowerShell("Get-LocalGroup | ForEach-Object { Write-Output \"Group: $($.Name)\"; Get-LocalGroupMember -Group $.Name | Select Name }"));
        info.put("Local Users", runPowerShell("Get-LocalUser | Format-Table Name,Enabled,LastLogon -HideTableHeaders"));
        info.put("Microsoft Updates", runPowerShell("(New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher().Search(\"IsInstalled=1\").Updates | Select Title"));
        info.put("NTLM Settings", runPowerShell("Get-ItemProperty -Path HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa"));
        info.put("Saved RDP Connections", runPowerShell("Get-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Terminal Server Client\\Default'"));
        info.put("Incoming RDP Sessions", runCommand("query session"));
        info.put("Remote Desktop Config", runPowerShell("Get-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server'"));
        info.put("Secure Boot Config", runPowerShell("Confirm-SecureBootUEFI"));
        info.put("Sysmon Config", runPowerShell("Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\SysmonDrv'"));
        info.put("UAC Policies", runPowerShell("Get-ItemProperty -Path HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"));
        info.put("PowerShell History Sensitive Info", runPowerShell("Get-Content (Get-PSReadlineOption).HistorySavePath | Select-String -Pattern 'password|secret|token|apikey'"));
        return info;
    }

    public static Map<String, String> collectNetworkInfo() {
        Map<String, String> info = new LinkedHashMap<>();
        info.put("ARP Table", runCommand("arp -a"));
        info.put("DNS Cache", runPowerShell("Get-DnsClientCache | Format-Table -HideTableHeaders"));
        info.put("Network Profiles", runPowerShell("Get-NetConnectionProfile"));
        info.put("Network Shares", runPowerShell("net share"));
        info.put("TCP/UDP Connections", runCommand("netstat -ano"));
        info.put("RPC Endpoints", runCommand("rpcdump")); // may require sysinternals or admin rights
        info.put("Open Ports", runCommand("netstat -an | findstr LISTENING"));
        info.put("System Interface Connectors", runPowerShell("Get-NetAdapter | Format-Table -HideTableHeaders"));
        info.put("LLDP/CDP Devices", runPowerShell("Get-NetNeighbor")); // partial LLDP info
        return info;
    }

    public static String runPowerShell(String command) {
        return runCommand("powershell.exe -Command \"" + command + "\"");
    }

    public static String runCommand(String command) {
        StringBuilder output = new StringBuilder();
        try {
            ProcessBuilder builder = new ProcessBuilder("cmd.exe", "/c", command);
            builder.redirectErrorStream(true);
            Process process = builder.start();
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }
            process.waitFor();
        } catch (IOException | InterruptedException e) {
            output.append("Error: ").append(e.getMessage());
        }
        return output.toString().trim();
    }

    public static void generateTextReport(Map<String, String> sysInfo, Map<String, String> netInfo, String filename) {
        try (PrintWriter writer = new PrintWriter(new FileWriter(filename))) {
            writer.println("Agent-less Windows System Vulnerability and Network Scanner Report");
            writer.println("Generated on: " + new Date());
            writer.println("------------------------------------------------------\n");

            writer.println("=== System Information ===\n");
            for (Map.Entry<String, String> entry : sysInfo.entrySet()) {
                writer.println("[" + entry.getKey() + "]\n" + entry.getValue() + "\n");
            }

            writer.println("=== Network Information ===\n");
            for (Map.Entry<String, String> entry : netInfo.entrySet()) {
                writer.println("[" + entry.getKey() + "]\n" + entry.getValue() + "\n");
            }
        } catch (IOException e) {
            System.err.println("Failed to write report: " + e.getMessage());
        }
    }
}