open V1_LWT
open Lwt
open Printf

open Ofswitch0x04
open Ofsocket0x04

let contaddr= "127.0.0.1"
let contport = 6633

module Main (C: CONSOLE)(S: STACKV4)(N0: NETWORK)(N1: NETWORK)(N2: NETWORK) = struct

  module T = S.TCPV4
  module Sw = Ofswitch0x04.Make(T)(N1)

  let start console s n0 n1 n2 =

  let dpid = 
  (* based on 1.4.0 - 7.3 *)
    let rec find_int_mac imac ind =
      match ind with
      | 6 -> imac
      | i -> let chr = Int64.of_int (int_of_char (Macaddr.to_bytes (N0.mac n0)).[i]) in
             let cmb = Int64.logor (Int64.shift_left imac 8) chr in
             find_int_mac cmb (i + 1)
   in
     let imac = find_int_mac Int64.zero 0 in
     (* TODO: possible use of VLAN ID *)
     let rnd = Int64.shift_left (Random.int64 0xffffL) (6 * 8) in
     Int64.logor imac rnd
  in
  let netl = [n1; n2] in
    C.log_s console 
      (sprintf "IP address: %s\n"
        (String.concat ", " (List.map Ipaddr.V4.to_string (S.IPV4.get_ip (S.ipv4 s)))))
    >>= fun e ->
        Sw.create_switch (S.tcpv4 s) (contaddr, contport) netl dpid

end
