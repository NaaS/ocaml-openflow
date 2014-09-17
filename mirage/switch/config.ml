open Mirage

let main = foreign "Unikernel.Main" (console @-> stackv4 @-> network @-> network @-> job)

let unix_libs =
  match get_mode () with 
  | `Unix -> ["mirage-clock-unix"] 
  | _ -> []

let net =
  try match Sys.getenv "NET" with
    | "direct" -> `Direct
    | "socket" -> `Socket
    | _ -> `Direct
  with Not_found -> `Direct

let dhcp =
  try match Sys.getenv "ADDR" with
    | "dhcp" -> `Dhcp
    | "static" -> `Static
  with Not_found -> `Dhcp

let stack console =
  match net, dhcp with 
  | `Direct, `Dhcp -> direct_stackv4_with_dhcp console tap0
  | `Direct, `Static -> direct_stackv4_with_default_ipv4 console tap0
  | `Direct, _ -> direct_stackv4_with_default_ipv4 console tap0
  | `Socket, _ -> socket_stackv4 console [Ipaddr.V4.any]

(*
  | _, _ -> socket_stackv4 console [Ipaddr.V4.any] (* for the controller test *)
*)
(*
  | _, _ -> direct_stackv4_with_default_ipv4 console tap0 (* for the controller test *)
*)

let () =
  add_to_ocamlfind_libraries
<<<<<<< HEAD
    ([ "tcpip.ethif"; "tcpip.tcpv4"; "tcpip.udpv4"; "tcpip.dhcpv4"; "tcpip.channel"; "cstruct.syntax"; "core_kernel"; "sexplib"; "sexplib.syntax"; "packet"; "openflow";] @ unix_libs);
=======
<<<<<<< HEAD
    ([ "tcpip.ethif"; "tcpip.tcpv4"; "tcpip.udpv4"; "tcpip.dhcpv4"; "tcpip.channel"; "cstruct.syntax"; "core_kernel"; "sexplib"; "sexplib.syntax"; "packet"; "openflow";] @ unix_libs);
=======
    ([ "tcpip.ethif"; "tcpip.tcpv4"; "tcpip.udpv4"; "tcpip.dhcpv4"; "tcpip.channel"; "cstruct.syntax"; "core_kernel"; "sexplib"; "sexplib.syntax"; "packet"; ] @ unix_libs);
>>>>>>> 22296d4920f547d23f60585fea475d558184914d
>>>>>>> 6df49db3cdbba5c9fff22b50b080c192ca0e1457

  register "ofswitch" [
    main $ default_console $ (stack default_console) $ (netif "tap1") $ (netif "tap2")
  ]
