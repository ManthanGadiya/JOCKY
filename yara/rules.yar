// YARA 4.5 - L7 Detection Engine (safe demo rules, like EICAR)
// Detects JOCKY polymorphic artifacts + BYOVD + hollowing + file/network signals in synthetic evidence
rule JOCKY_DEMO_MARKER {
  meta: description="JOCKY demo artifact - polymorphic IR marker"
        mitre="T1055"
        severity="HIGH"
  strings: $a="JOCKY_DEMO_MARKER"
  condition: $a
}
rule BYOVD_RTCore64 {
  meta: description="Vulnerable driver RTCore64 (BYOVD T1068)"
        mitre="T1068"
        severity="CRITICAL"
  strings: $a="RTCore64" $b="RTCore64.sys" $c="rtc_core"
  condition: any of them
}
rule Process_Hollowing {
  meta: description="Hollowed process - unbacked RX private memory"
        mitre="T1055.012"
        severity="CRITICAL"
  strings: $a="hollowed" nocase $b="MEM_PRIVATE" $c="unbacked"
  condition: 2 of them
}
rule File_Suspicious_PE {
  meta: description="Suspicious file marker for demo PE"
        mitre="T1105"
        severity="HIGH"
  strings: $a="sample.exe" $b="malware.exe" nocase $c="suspicious" nocase
  condition: any of them
}
rule Network_C2_Beacon {
  meta: description="C2 beacon remote IP 192.0.2.20"
        mitre="T1071"
        severity="HIGH"
  strings: $a="192.0.2.20" $b="C2 beacon"
  condition: any of them
}
