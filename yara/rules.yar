// YARA 4.5 - L7 Detection Engine (safe demo rules, like EICAR)
// Detects JOCKY polymorphic artifacts + BYOVD + hollowing markers in synthetic evidence
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
  strings: $a="RTCore64" $b="RTCore64.sys"
  condition: any of them
}
rule Process_Hollowing {
  meta: description="Hollowed process - unbacked RX private memory"
        mitre="T1055.012"
        severity="CRITICAL"
  strings: $a="hollowed" nocase $b="MEM_PRIVATE" $c="unbacked"
  condition: 2 of them
}
