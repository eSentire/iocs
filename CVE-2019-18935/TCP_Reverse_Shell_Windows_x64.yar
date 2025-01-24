rule TCP_Reverse_Shell_Windows_x64 {
   meta:
      description = "Detects Windows based 64-bit TCP reverse shell"
      author = "YungBinary"
      date = "2025-01-23"
      hash = "b971bf43886e3ab1d823477826383dfaee1e2935788226a285c7aebeabee7348"
   strings:
      $winsock_2_0   = { 66 B? 02 00 FF 15 }
      $winsock_2_1   = { 66 B? 02 01 FF 15 }
      $winsock_2_2   = { 66 B? 02 02 FF 15 }
      $winsock_1_0   = { 66 B? 01 00 FF 15 }
      $winsock_1_1   = { 66 B? 01 01 FF 15 }

      $socket_params = {
        41 B8 06 00 00 00
        BA 01 00 00 00 
        B9 02 00 00 00 
      }

      $cmd = {
        48 C7 44 24 ?? 00 00 00 00
        48 C7 44 24 ?? 00 00 00 00
        C7 44 24 ?? 00 00 00 00
        C7 44 24 ?? (01 | 00) 00 00 00
        45 33 C9
        45 33 C0
        48 8D 15 ?? ?? ?? ??
        33 C9
        FF 15
      }
    
      $wait = {
        BA FF FF FF FF
        48 8B 4C ?? ??
        FF 15
      }

   condition:
      uint16(0) == 0x5a4d and ((1 of ($winsock*)) and $socket_params and $cmd and $wait)
}
