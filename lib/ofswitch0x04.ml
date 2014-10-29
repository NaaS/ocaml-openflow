(*
 * Copyright (c) 2014 Masoud Koleini <masoud.koleini@nottingham.ac.uk>
 * Copyright (c) 2011 Richard Mortier <mort@cantab.net>
 * Copyright (c) 2014 Charalampos Rotsos <cr409@cl.cam.ac.uk>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *)

open V1_LWT
open Lwt
open Packet

open OpenFlow0x04
open OpenFlow0x04_Core

module Message = OpenFlow0x04.Message

exception Packet_type_unknw
exception Unparsable of string * Cstruct.t 
exception Unparsed of string * Cstruct.t 
exception Unsupported of string
exception Overlap

let sp = Printf.sprintf
let pp = Printf.printf
let ep = Printf.eprintf

type cookie = int64

let resolve t = Lwt.on_success t (fun _ -> ())

let hello_sent = ref false

let max_table_num = 10

let get_new_buffer len = 
  let buf = Io_page.to_cstruct (Io_page.get 1) in 
    Cstruct.sub buf 0 len 

(* XXX any possible replacement? *)
let or_error name fn t =
  fn t
  >>= function
	| `Error e -> fail (Failure ("Error starting " ^ name))
    | `Ok t -> let _ = (pp "%s works...\n" name) in
			   return t

module Entry = struct

  type flow_counter = {
    mutable n_packets: int64;
    mutable n_bytes: int64;
    flags : flowModFlags;
    priority: int16;
    cookie: cookie mask;
    insert_sec: int;
    insert_nsec: int;
    mutable last_sec: int;
    mutable last_nsec: int;
    idle_timeout: timeout;
    hard_timeout:timeout;
  }

  type queue_counter = {
    tx_queue_packets: int64;
    tx_queue_bytes: int64;
    tx_queue_overrun_errors: int64;
  }

  let init_flow_counters flowmod = (* we may require more information to save *)
    let ts = int_of_float (Clock.time ()) in
    ({n_packets=0L; n_bytes=0L;
	  priority=flowmod.mfPriority; cookie=flowmod.mfCookie; (* XXX what to do? *)
	  insert_sec=ts; insert_nsec=0; (* XXX Do we need nsec? timeouts are in sec *)
	  last_sec=ts; last_nsec=0; idle_timeout=flowmod.mfIdle_timeout; hard_timeout=flowmod.mfHard_timeout;
	  flags=flowmod.mfFlags; })

  (* flow entry *)
  type t = { 
    mutable cache_entries: OfpMatch.t list;
    counters: flow_counter;
    instructions: instruction list;
  }

  let update_flow pkt_len flow = 
    flow.counters.n_packets <- Int64.add flow.counters.n_packets 1L;
    flow.counters.n_bytes <- Int64.add flow.counters.n_bytes pkt_len;
    flow.counters.last_sec <- int_of_float (Clock.time ())

  let flow_counters_to_flow_stats ofp_match table_id flow = (* return type: individualStats *)
   	{table_id
	; duration_sec = Int32.of_int (flow.counters.last_sec - flow.counters.insert_sec)
	; duration_nsec = Int32.of_int (flow.counters.last_nsec - flow.counters.insert_nsec)
	; priority = flow.counters.priority
	; idle_timeout = flow.counters.idle_timeout
	; hard_timeout = flow.counters.hard_timeout
	; flags = flow.counters.flags
	; cookie = flow.counters.cookie.m_value (* XXX note: flow stats doesn't have mask... what does it mean? *)
	; packet_count = flow.counters.n_packets
	; byte_count = flow.counters.n_bytes
	; instructions = flow.instructions
	; ofp_match}

end


module SwMatch = struct

  cstruct dl_header {
    uint8_t   dl_dst[6];
    uint8_t   dl_src[6]; 
    uint16_t  dl_type 
  } as big_endian

  cstruct arphdr {
    uint16_t ar_hrd;         
    uint16_t ar_pro;         
    uint8_t ar_hln;              
    uint8_t ar_pln;              
    uint16_t ar_op;          
    uint8_t ar_sha[6];  
    uint32_t nw_src;
    uint8_t ar_tha[6];  
    uint32_t nw_dst 
  } as big_endian

  cstruct nw_header {
    uint8_t        hlen_version;
    uint8_t        nw_tos;
    uint16_t       total_len;
    uint8_t        pad[5];
    uint8_t        nw_proto; 
    uint16_t       csum;
    uint32_t       nw_src; 
    uint32_t       nw_dst
  } as big_endian 

  cstruct ipv6_header {
    uint32_t       version_class_flow;
    uint16_t       payload_len;
    uint8_t        next_header;
    uint8_t        hop_limit; 
    uint64_t       nw_src1;
    uint64_t       nw_src2; 
    uint64_t       nw_dst1;
    uint64_t       nw_dst2; 
  } as big_endian 

  cstruct tp_header {
    uint16_t tp_src;
    uint16_t tp_dst
  } as big_endian 

  cstruct icmphdr {
    uint8_t typ;
    uint8_t code;
    uint16_t checksum
  } as big_endian

  cstruct icmpv6_m135_m136 {
    uint32_t header;
    uint32_t res;
    uint64_t nw_dst1;
    uint64_t nw_dst2;
	uint32_t options;
  } as big_endian

  cstruct tcpv4 {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t sequence;
    uint32_t ack_number;
    uint32_t  dataoff_flags_window;
    uint16_t checksum
  } as big_endian

  cstruct pseudo_header {
    uint32_t src;
    uint32_t dst;
    uint8_t res;
    uint8_t proto;
    uint16_t len
  } as big_endian 

  let oxm_to_num m =
	match m with
	| OxmInPort _ 		-> 0
	| OxmInPhyPort _	-> 1
	| OxmMetadata _		-> 2
	| OxmEthType _		-> 3
	| OxmEthDst _		-> 4
	| OxmEthSrc _		-> 5
	| OxmVlanVId _		-> 6
	| OxmVlanPcp _		-> 7
	| OxmIPProto _		-> 8
	| OxmIPDscp _		-> 9
	| OxmIPEcn _		-> 10
	| OxmIP4Src _		-> 11
	| OxmIP4Dst _		-> 12
	| OxmTCPSrc _		-> 13
	| OxmTCPDst _		-> 14
	| OxmARPOp _		-> 15
	| OxmARPSpa _		-> 16
	| OxmARPTpa _		-> 17
	| OxmARPSha _		-> 18
	| OxmARPTha _		-> 19
	| OxmICMPType _		-> 20
	| OxmICMPCode _		-> 21
	| OxmMPLSLabel _	-> 22
	| OxmMPLSTc _		-> 23
	| OxmTunnelId _		-> 24
	| OxmUDPSrc _		-> 25
	| OxmUDPDst _		-> 26
	| OxmSCTPSrc _		-> 27
	| OxmSCTPDst _		-> 28
	| OxmIPv6Src _		-> 29
	| OxmIPv6Dst _		-> 30
	| OxmIPv6FLabel _	-> 31
	| OxmICMPv6Type _	-> 32
	| OxmICMPv6Code _	-> 33
	| OxmIPv6NDTarget _	-> 34
	| OxmIPv6NDSll _	-> 35
	| OxmIPv6NDTll _	-> 36
	| OxmMPLSBos _		-> 37
	| OxmPBBIsid _		-> 38
	| OxmIPv6ExtHdr _	-> 39

  (* TODO: sort ofpMatch sent by controller before any processing ... *)
  let sort_of_match m1 m2 = (oxm_to_num m1) - (oxm_to_num m2)


  let raw_packet_to_match in_port bits = (* builds openflow match in order *)
	let ethDst = Packet.mac_of_bytes (Cstruct.to_string (get_dl_header_dl_dst bits)) in
    let ethSrc = Packet.mac_of_bytes (Cstruct.to_string (get_dl_header_dl_src bits)) in
    let eth_type = get_dl_header_dl_type bits in
    let bits = Cstruct.shift bits sizeof_dl_header in 
	let network = [OxmInPort in_port; OxmEthType eth_type;
				   OxmEthDst (val_to_mask ethDst); OxmEthSrc (val_to_mask ethSrc)] in
    match (eth_type) with 
    | 0x0800 -> begin (* IPv4 *)
      let nw_src = get_nw_header_nw_src bits in 
      let nw_dst = get_nw_header_nw_dst bits in 
      let nw_proto = get_nw_header_nw_proto bits in 
      let nw_tos = get_nw_header_nw_tos bits in 
      let len = (get_nw_header_hlen_version bits) land 0xf in 
      let bits = Cstruct.shift bits (len*4) in
	  let network_ip =
			network @ [OxmIPProto nw_proto; OxmIPDscp (nw_tos lsr 2); OxmIPEcn (nw_tos land 3);
					   OxmIP4Src (val_to_mask nw_src); OxmIP4Dst (val_to_mask nw_dst);]
	  in
	    network_ip @ (
        match (nw_proto) with
        | 1  -> [OxmICMPType (get_icmphdr_typ bits); OxmICMPCode (get_icmphdr_code bits)]
        | 6  -> [OxmTCPSrc (get_tp_header_tp_src bits); OxmTCPDst (get_tp_header_tp_dst bits)]
        | 17 -> [OxmUDPSrc (get_tp_header_tp_src bits); OxmUDPDst (get_tp_header_tp_dst bits)]
        | 58 -> let typ = get_icmphdr_typ bits in
				[OxmICMPv6Type typ; OxmICMPv6Code (get_icmphdr_code bits)] @ (
				match typ with
				| 135 -> let ipv6NDTarget = (get_icmpv6_m135_m136_nw_dst1 bits, get_icmpv6_m135_m136_nw_dst2 bits) in
					[OxmIPv6NDTarget (val_to_mask ipv6NDTarget)]
				(* TODO ipv6NDSll *)
				| 136 -> let ipv6NDTarget = (get_icmpv6_m135_m136_nw_dst1 bits, get_icmpv6_m135_m136_nw_dst2 bits) in
					[OxmIPv6NDTarget (val_to_mask ipv6NDTarget)]
				(* TODO ipv6NDTll *)
				)
		| 132-> [OxmSCTPSrc (get_tp_header_tp_src bits); OxmSCTPDst (get_tp_header_tp_dst bits)]
		(* TODO | _ -> raise error *)
		)
      end 
    | 0x86dd -> (* IPv6 : TODO *)
		network @ [
		  OxmIPv6Src (val_to_mask (get_ipv6_header_nw_src1 bits, get_ipv6_header_nw_src2 bits))
		; OxmIPv6Dst (val_to_mask (get_ipv6_header_nw_dst1 bits, get_ipv6_header_nw_dst2 bits))
		; OxmIPv6FLabel (val_to_mask (Int32.logand (get_ipv6_header_version_class_flow bits) (Int32.of_int 0xfffff)))
		]
    | 0x0806 -> (* ARP :TODO *)
		network @ [
		  OxmARPOp (get_arphdr_ar_op bits)
		; OxmARPSpa (val_to_mask (get_arphdr_nw_src bits))
		; OxmARPTpa (val_to_mask (get_arphdr_nw_dst bits))
		; OxmARPSha (val_to_mask (Packet.mac_of_bytes (Cstruct.to_string (get_arphdr_ar_sha bits))))
		; OxmARPTha (val_to_mask (Packet.mac_of_bytes (Cstruct.to_string (get_arphdr_ar_tha bits))))
		]
    | _ ->  (* TODO MPLS and ... *)
		network


  (* XXX considering that of_match lists are ordered in the same way *)
  let rec check_flow_overlap flow flow_patten =
	let check_with_mask f f_p logical_and =
	  match f, f_p with (* definition of mask is changed in openflow 1.4.0 *)
	  | {m_value = v; m_mask = None}, {m_value = v_p; m_mask = None} -> v = v_p
	  | {m_value = v; m_mask = Some m}, {m_value = v_p; m_mask = Some m_p} ->
		  (logical_and v m) = (logical_and v_p m_p)
	  | _, _ -> false
	in
	let check cond tx ty =
		if cond then check_flow_overlap tx ty else false
	in
	match flow, flow_patten with
	| [], _ | _, [] -> true

	| (OxmInPort x)::tx, (OxmInPort y)::ty
	| (OxmInPhyPort x)::tx, (OxmInPhyPort y)::ty 
	| (OxmMPLSLabel x)::tx, (OxmMPLSLabel y)::ty
		-> check (x = y) tx ty
	| (OxmEthType x)::tx, (OxmEthType y)::ty
	| (OxmTCPSrc x)::tx, (OxmTCPSrc y)::ty
	| (OxmTCPDst x)::tx, (OxmTCPDst y)::ty
	| (OxmARPOp x)::tx, (OxmARPOp y)::ty
	| (OxmICMPType x)::tx, (OxmICMPType y)::ty
	| (OxmICMPCode x)::tx, (OxmICMPCode y)::ty
	| (OxmMPLSTc x)::tx, (OxmMPLSTc y)::ty
	| (OxmUDPSrc x)::tx, (OxmUDPSrc y)::ty
	| (OxmUDPDst x)::tx, (OxmUDPDst y)::ty
	| (OxmSCTPSrc x)::tx, (OxmSCTPSrc y)::ty
	| (OxmSCTPDst x)::tx, (OxmSCTPDst y)::ty
	| (OxmICMPv6Type x)::tx, (OxmICMPv6Type y)::ty
	| (OxmICMPv6Code x)::tx, (OxmICMPv6Code y)::ty
		-> check (x = y) tx ty
	| (OxmEthDst x)::tx, (OxmEthDst y)::ty 
	| (OxmEthSrc x)::tx, (OxmEthSrc y)::ty 
	| (OxmARPSha x)::tx, (OxmARPSha y)::ty 
	| (OxmARPTha x)::tx, (OxmARPTha y)::ty
	| (OxmTunnelId x)::tx, (OxmTunnelId y)::ty
		-> check (check_with_mask x y Int64.logand) tx ty
	| (OxmVlanPcp x)::tx, (OxmVlanPcp y)::ty
	| (OxmIPProto x)::tx, (OxmIPProto y)::ty
	| (OxmIPDscp x)::tx, (OxmIPDscp y)::ty
	| (OxmIPEcn x)::tx, (OxmIPEcn y)::ty
		-> check (x = y) tx ty
	| (OxmIP4Src x)::tx, (OxmIP4Src y)::ty 
	| (OxmIP4Dst x)::tx, (OxmIP4Dst y)::ty 
	| (OxmARPSpa x)::tx, (OxmARPSpa y)::ty 
	| (OxmARPTpa x)::tx, (OxmARPTpa y)::ty 
	| (OxmIPv6FLabel x)::tx, (OxmIPv6FLabel y)::ty 
	| (OxmPBBIsid x)::tx, (OxmPBBIsid y)::ty 
		-> check (check_with_mask x y Int32.logand) tx ty
	| (OxmIPv6NDSll x)::tx, (OxmIPv6NDSll y)::ty
	| (OxmIPv6NDTll x)::tx, (OxmIPv6NDTll y)::ty
		-> check (x = y) tx ty
	| (OxmMPLSBos x)::tx, (OxmMPLSBos y)::ty
		-> check (x = y) tx ty
(*	| (OxmVlanVId x)::tx, (OxmVlanVId y)::ty
		-> false
	| (OxmIPv6Src x)::tx, (OxmIPv6Src y)::ty
	| (OxmIPv6Dst x)::tx, (OxmIPv6Dst y)::ty
		-> false
	| (OxmIPv6NDTarget x)::tx, (OxmIPv6NDTarget y)::ty
		-> false *)
	| ofmx::tx, ofmy::ty -> if (oxm_to_num ofmx) < (oxm_to_num ofmy) then
								check_flow_overlap tx flow_patten
							else
								check_flow_overlap flow ty
	(* oxmIPv6ExtHdr? *)

  (* XXX considering that of_match lists are ordered in the same way *)
  let rec check_flow_del_modify flow flow_patten =
	let check_with_mask f f_p logical_and =
	  match f, f_p with (* definition of mask has changed in openflow 1.4.0 *)
	  | {m_value = v; m_mask = None}, {m_value = v_p; m_mask = None} -> v = v_p
	  | {m_value = v; m_mask = Some m}, {m_value = v_p; m_mask = Some m_p} -> (* XXX check for del+mod *)
		  (logical_and v m) = (logical_and v_p m_p)
	  | _, _ -> false
	in
	let check cond tx ty =
		if cond then check_flow_overlap tx ty else false
	in
	match flow, flow_patten with
	| [], _ | _, [] -> true

	| (OxmInPort x)::tx, (OxmInPort y)::ty
	| (OxmInPhyPort x)::tx, (OxmInPhyPort y)::ty 
	| (OxmMPLSLabel x)::tx, (OxmMPLSLabel y)::ty
		-> check (x = y) tx ty
	| (OxmEthType x)::tx, (OxmEthType y)::ty
	| (OxmTCPSrc x)::tx, (OxmTCPSrc y)::ty
	| (OxmTCPDst x)::tx, (OxmTCPDst y)::ty
	| (OxmARPOp x)::tx, (OxmARPOp y)::ty
	| (OxmICMPType x)::tx, (OxmICMPType y)::ty
	| (OxmICMPCode x)::tx, (OxmICMPCode y)::ty
	| (OxmMPLSTc x)::tx, (OxmMPLSTc y)::ty
	| (OxmUDPSrc x)::tx, (OxmUDPSrc y)::ty
	| (OxmUDPDst x)::tx, (OxmUDPDst y)::ty
	| (OxmSCTPSrc x)::tx, (OxmSCTPSrc y)::ty
	| (OxmSCTPDst x)::tx, (OxmSCTPDst y)::ty
	| (OxmICMPv6Type x)::tx, (OxmICMPv6Type y)::ty
	| (OxmICMPv6Code x)::tx, (OxmICMPv6Code y)::ty
		-> check (x = y) tx ty
	| (OxmEthDst x)::tx, (OxmEthDst y)::ty 
	| (OxmEthSrc x)::tx, (OxmEthSrc y)::ty 
	| (OxmARPSha x)::tx, (OxmARPSha y)::ty 
	| (OxmARPTha x)::tx, (OxmARPTha y)::ty
	| (OxmTunnelId x)::tx, (OxmTunnelId y)::ty
		-> check (check_with_mask x y Int64.logand) tx ty
	| (OxmVlanPcp x)::tx, (OxmVlanPcp y)::ty
	| (OxmIPProto x)::tx, (OxmIPProto y)::ty
	| (OxmIPDscp x)::tx, (OxmIPDscp y)::ty
	| (OxmIPEcn x)::tx, (OxmIPEcn y)::ty
		-> check (x = y) tx ty
	| (OxmIP4Src x)::tx, (OxmIP4Src y)::ty 
	| (OxmIP4Dst x)::tx, (OxmIP4Dst y)::ty 
	| (OxmARPSpa x)::tx, (OxmARPSpa y)::ty 
	| (OxmARPTpa x)::tx, (OxmARPTpa y)::ty 
	| (OxmIPv6FLabel x)::tx, (OxmIPv6FLabel y)::ty 
	| (OxmPBBIsid x)::tx, (OxmPBBIsid y)::ty 
		-> check (check_with_mask x y Int32.logand) tx ty
	| (OxmIPv6NDSll x)::tx, (OxmIPv6NDSll y)::ty
	| (OxmIPv6NDTll x)::tx, (OxmIPv6NDTll y)::ty
		-> check (x = y) tx ty
	| (OxmMPLSBos x)::tx, (OxmMPLSBos y)::ty
		-> check (x = y) tx ty
(*	| (OxmVlanVId x)::tx, (OxmVlanVId y)::ty
		-> false
	| (OxmIPv6Src x)::tx, (OxmIPv6Src y)::ty
	| (OxmIPv6Dst x)::tx, (OxmIPv6Dst y)::ty
		-> false
	| (OxmIPv6NDTarget x)::tx, (OxmIPv6NDTarget y)::ty
		-> false *)
	| ofmx::tx, ofmy::ty -> if (oxm_to_num ofmx) < (oxm_to_num ofmy) then
								check_flow_overlap tx flow_patten
							else
								false (* this is the difference with overlapping.
										 if entry is less specific than pattern (flow description)
										 then it should not be deleted.
									  *)
	(* oxmIPv6ExtHdr? *)
end

module Make(T:TCPV4 (* controller *))(N:NETWORK) = struct

  module E = Ethif.Make(N)
  module Channel = Channel.Make(T)
  module OSK = Ofsocket0x04.Make(T)

  type eth_t = E.t 

  type port = {
    port_id: portId;
    ethif: E.t;
    port_name: string;
    mutable counter: portStats;
    phy: portDesc;
    in_queue: Cstruct.t Lwt_stream.t;
    in_push : (Cstruct.t option -> unit);
    out_queue: Cstruct.t Lwt_stream.t;
    out_push : (Cstruct.t option -> unit);
    mutable pkt_count : int;
  }

  let rec is_output_port out_port = 
	let rec is_output = function
		| [] -> false
		| Output (PhysicalPort portId) ::_ when (portId = out_port) -> true
		| h::t -> is_output t
	in
	function 
	| [] -> false
	| (ApplyActions h)::t -> if is_output h then true else is_output_port out_port t 
	| _::t -> is_output_port out_port t

  let rec is_output_group out_group = (* XXX combine it with is_output_port to become one function *)
	let rec is_output = function
		| [] -> false
		| Group groupId ::_ when (groupId = out_group) -> true
		| h::t -> is_output t
	in
	function 
	| [] -> false
	| (ApplyActions h)::t -> if is_output h then true else is_output_port out_group t 
	| _::t -> is_output_port out_group t


  module Table = struct

	type table_counter = {
	  mutable n_active: int32;
	  mutable n_lookups: int64;
	  mutable n_matches: int64;
	}

	type t = {
	  tid: tableId; (* XXX why we have cookie in both table and entry module? Do we need it for Table? *)

	  (* This entry stores wildcard and exact match entries as
	   * transmitted by the controller *)

	  (* XXX Match fileds (OfpMatch) + priority is unique in table.
		We keep a list of entries that are different in priority for each OfpMatch.
		Therefore, entries will have unique OfpMatch *)
	  (* XXX IMPORTANT: for not to modify a huge bunch of code, I keep table structure 
		 as before. It has to be fixed later *)
	  mutable entries: (OfpMatch.t, Entry.t) Hashtbl.t;

	  (* Intermediate table to store exact match flows deriving from wildcard
	   * entries *)

	  (* XXX each entry contains a list of header fields. Why we have one per entry here? *)
	  (* XXX IMPORTANT: get rid of cache. No performance enhancement with current structure *)
	  mutable cache : (OfpMatch.t, Entry.t ref) Hashtbl.t;
	  (* stats : OP.Stats.table; *) (* removed for now *)

	  mutable counter : table_counter; (* TODO: update it *)
	}

	let init_table id =
		{ tid = id; entries = (Hashtbl.create 10000); cache = (Hashtbl.create 10000);
		  counter = {n_active = 0l; n_lookups = 0L; n_matches = 0L}
		}

	let rec init_tables id =
	  if id < max_table_num then
		(init_table id) :: init_tables (id + 1)
	  else
		[]

	let add_flow table ?(xid=Random.int32 Int32.max_int) (fm : flowMod) conn verbose =
	  let non_overlap = (* check overlap *)
		if (fm.mfFlags.fmf_check_overlap) then
		  try
			let _ = Hashtbl.iter (
			  fun of_match entry -> 
				if (SwMatch.check_flow_overlap of_match fm.mfOfp_match &&
					entry.Entry.counters.priority = fm.mfPriority) then 
				  raise Overlap
          	) table.entries
			in
			  true
		  with Overlap -> false
		else
		  true
	  in
		match non_overlap with
		| true ->
			let entry = Entry.({
						  instructions=fm.mfInstructions
						; counters=(init_flow_counters fm)
						; cache_entries=[]
						}) in  
			let _ = Hashtbl.replace table.entries fm.mfOfp_match entry in
			let _ = 
			  Hashtbl.iter (
				fun a e -> 
				  if ((SwMatch.check_flow_overlap a fm.mfOfp_match) &&
				      Entry.(entry.counters.priority >= (!e).counters.priority)) then ( 
				        let _ = (!e).Entry.cache_entries <- 
				          List.filter (fun c -> a <> c) (!e).Entry.cache_entries in 
				        let _ = Hashtbl.replace table.cache a (ref entry) in 
				          entry.Entry.cache_entries <- a :: entry.Entry.cache_entries
				      )
			  ) table.cache in
			let _ = if (verbose) then 
			  pp "[switch] Adding flow %s\n" (OfpMatch.to_string fm.mfOfp_match)
			in
			  return ()
		| false ->
			let _ = if (verbose) then
			  pp "[switch] add_flow overlap error!";
			in
			  OSK.send_packet conn (Message.marshal xid (Error {err = FlowModFailed FlOverlap; data = Cstruct.create 0}))

  let marshal_optional t = match t with (* from OF *)
    | None -> 0xffffl (* OFPP_NONE *)
    | Some x -> PseudoPort.marshal x


  (* TODO: match with p37 of 1.4 manual after modifying entry data type in the table *)
  let del_flow table ?(xid=Random.int32 Int32.max_int)
			?(reason=FlowDelete) dflow out_port conn verbose =

	let port_num = marshal_optional out_port in
    (* Delete all matching entries from the flow table*)
    let remove_flow = 
      Hashtbl.fold (
        fun of_match flow ret -> 
          if ((SwMatch.check_flow_overlap of_match dflow) && (* remove overlappings or exact matches? *)
              ((port_num = 0xffffl) ||
               (is_output_port port_num flow.Entry.instructions))) then ( 
            let _ = Hashtbl.remove table.entries of_match in 
               (of_match, flow)::ret
          ) else ret
          ) table.entries [] in

    (* Delete all entries from cache *) 
    let _ = 
      List.iter (
        fun (_, flow) -> 
          List.iter (Hashtbl.remove table.cache) flow.Entry.cache_entries
      ) remove_flow in 

    (* Check for notification flag in flow and send 
    * flow modification warnings *)
      Lwt_list.iter_s (
      fun (of_match, flow) ->
        let _ = 
          if verbose then
            pp "[switch] Removing flow %s" (OfpMatch.to_string of_match)
        in 
        match(conn, flow.Entry.counters.flags.fmf_send_flow_rem) with
        | (Some t, true) -> 
          let duration_sec = (int_of_float (Clock.time ()))  -
            flow.Entry.counters.Entry.insert_sec in
          let fl_rm = (
			{ cookie = flow.Entry.counters.Entry.cookie.m_value
			; priority = flow.Entry.counters.Entry.priority
			; reason
			; table_id = table.tid
			; duration_sec = (Int32.of_int duration_sec)
			; duration_nsec = 0l
			; idle_timeout = flow.Entry.counters.Entry.idle_timeout
			; hard_timeout = flow.Entry.counters.Entry.hard_timeout
			; packet_count = flow.Entry.counters.Entry.n_packets
			; byte_count = flow.Entry.counters.Entry.n_bytes
			; oxm = of_match }
		) in
			OSK.send_packet t (Message.marshal xid (FlowRemoved fl_rm))
        | _ -> return ()
    ) remove_flow


	(* table stat update methods *)
(*
	let update_table_found table =
	  let open OP.Stats in 
		table.stats.lookup_count <- Int64.add table.stats.lookup_count 1L;
		table.stats.matched_count <- Int64.add table.stats.matched_count 1L

	let update_table_missed table =
	  let open OP.Stats in 
		table.stats.lookup_count <- Int64.add table.stats.lookup_count 1L
*)	
	  (* monitor thread to timeout flows *)
	let monitor_flow_timeout tables t verbose = 
	  let open Entry in
		let check_flow_timeout table t verbose = 
		  let ts = int_of_float (Clock.time ()) in 
		  let flows = Hashtbl.fold (
		    fun of_match entry ret -> 
		      let hard = ts - entry.counters.insert_sec in
		      let idle = ts - entry.counters.last_sec in
		      match (hard, idle) with 
		        | (l, _) -> begin
						match entry.counters.hard_timeout with
						| ExpiresAfter x when (x > 0 && l >= x) ->
							(of_match, entry, FlowHardTiemout )::ret
						| _ -> ret
						end
		        | (_, l) -> begin (* TODO: this match case is unused! fix *)
						match entry.counters.idle_timeout with
						| ExpiresAfter x when (x > 0 && l >= x) ->
							ret @ [(of_match, entry, FlowIdleTimeout )]
						| _ -> ret
						end
		  ) table.entries [] in 
		    Lwt_list.iter_s (
		      fun (of_match, entry, reason) -> 
		        del_flow table ~reason of_match None (* output port *) t verbose (* XXX important: check *)
		    ) flows
		in
		while_lwt true do 
		  lwt _ = OS.Time.sleep 1.0 in
			Lwt_list.iter_s (fun tbl -> check_flow_timeout tbl t verbose) tables
		done 

	end
  (* end of module table *)

  let init_port port_no ethif =
    let name = "" in						(* TODO *)
	let hw_addr = Packet.mac_of_string (Macaddr.to_string (E.mac ethif)) in
    let (in_queue, in_push) = Lwt_stream.create () in
    let (out_queue, out_push) = Lwt_stream.create () in
    let counter = 
        { psPort_no=port_no; rx_packets=0L; tx_packets=0L; rx_bytes=0L; 
          tx_bytes=0L; rx_dropped=0L; tx_dropped=0L; rx_errors=0L; 
          tx_errors=0L; rx_frame_err=0L; rx_over_err=0L; rx_crc_err=0L; 
          collisions=0L; duration_sec=0l; duration_nsec=0l}
	in
    let features =								(* XXX all rates are set to true *)
		{ rate_10mb_hd=true; rate_10mb_fd=true; rate_100mb_hd=true; rate_100mb_fd=true;
      	  rate_1gb_hd=true; rate_1gb_fd=true; rate_10gb_fd=true; rate_40gb_fd=true;
      	  rate_100gb_fd=true; rate_1tb_fd=true; other=true; copper=true; fiber=true;
      	  autoneg=true; pause=true; pause_asym=true }  
	in
    let config = { port_down=false; no_recv=false; no_fwd=false; no_packet_in=false } in 
    let state = { link_down=false; blocked=false; live=true } in (* XXX liveness *)
    let phy = 
		{ port_no; hw_addr; name; config; 
          state; curr=features; advertised=features;
		  supported=features; peer=features;
          curr_speed=0x3ffl; max_speed=0xfffffl}
	in
    {port_id=port_no; port_name=name; counter; 
	 ethif=ethif; phy; in_queue; in_push; pkt_count=0;
	 out_queue; out_push;}

  type stats = {
    mutable n_frags: int64;
    mutable n_hits: int64;
    mutable n_missed: int64;
    mutable n_lost: int64;
  }

  type lookup_ret = 
       | Found of OfpMatch.t * (Entry.t ref)
       | NOT_FOUND

  type t = {
    mutable int_to_port: (int32, port ref) Hashtbl.t;
    mutable ports : port list;
    mutable controller: OSK.conn_state option;
    mutable last_echo_req : float;
    mutable echo_resp_received : bool;
    table: Table.t list;
    stats: stats;
    mutable errornum : int32;
    mutable portnum : int32;
    mutable features' : SwitchFeatures.t;
    mutable packet_buffer: (int32 * bytes) list; (* to store frames *)
    mutable packet_buffer_id: int32;
    ready : unit Lwt_condition.t;
    verbose : bool;
    mutable pkt_len : int;
  }
(*
 let supported_actions () =
   SwitchFeatures.SupportedActions.({ output=true; set_vlan_id=true; set_vlan_pcp=true; strip_vlan=true;
   set_dl_src=true; set_dl_dst=true; set_nw_src=true; set_nw_dst=true;
   set_nw_tos=true; set_tp_src=true; set_tp_dst=true; enqueue=false;vendor=true; })
*)

  let supported_capabilities () = 
	{ flow_stats=true; table_stats=true; port_stats=true
	; group_stats=true; ip_reasm=false; queue_stats=false
	; port_blocked=false } (* XXX check queue_stats and port_blocked *)

  let switch_features datapath_id = 
	SwitchFeatures.({
	  datapath_id; num_buffers=0l; num_tables=1; aux_id=0; (* XXX check aux *)
      supported_capabilities=(supported_capabilities ())})

  let update_port_tx_stats pkt_len (port : port)=
	port.counter <-
		{ psPort_no = port.counter.psPort_no
		; rx_packets = port.counter.rx_packets
		; tx_packets = (Int64.add port.counter.tx_packets 1L)
		; rx_bytes = port.counter.rx_bytes
		; tx_bytes = (Int64.add port.counter.tx_bytes pkt_len)
		; rx_dropped = port.counter.rx_dropped
		; tx_dropped = port.counter.tx_dropped
		; rx_errors = port.counter.rx_errors
		; tx_errors = port.counter.tx_errors
		; rx_frame_err = port.counter.rx_frame_err
		; rx_over_err = port.counter.rx_over_err
		; rx_crc_err = port.counter.rx_crc_err
		; collisions = port.counter.collisions
		; duration_sec = port.counter.duration_sec
		; duration_nsec = port.counter.duration_nsec}

  let update_port_rx_stats pkt_len (port : port) = 
	port.counter <-
		{ psPort_no = port.counter.psPort_no
		; rx_packets = Int64.add port.counter.rx_packets 1L
		; tx_packets = port.counter.tx_packets
		; rx_bytes = Int64.add port.counter.rx_bytes pkt_len
		; tx_bytes = port.counter.tx_bytes
		; rx_dropped = port.counter.rx_dropped
		; tx_dropped = port.counter.tx_dropped
		; rx_errors = port.counter.rx_errors
		; tx_errors = port.counter.tx_errors
		; rx_frame_err = port.counter.rx_frame_err
		; rx_over_err = port.counter.rx_over_err
		; rx_crc_err = port.counter.rx_crc_err
		; collisions = port.counter.collisions
		; duration_sec = port.counter.duration_sec
		; duration_nsec = port.counter.duration_nsec}

  (* we have exactly the same function in pcb.mli *)
  let tcp_checksum ~src ~dst =
	let open SwMatch in
    let pbuf = Cstruct.sub (Cstruct.of_bigarray (Io_page.get 1)) 0 sizeof_pseudo_header in
    fun data ->
      set_pseudo_header_src pbuf (Ipaddr.V4.to_int32 src);
      set_pseudo_header_dst pbuf (Ipaddr.V4.to_int32 dst);
      set_pseudo_header_res pbuf 0;
      set_pseudo_header_proto pbuf 6;
      set_pseudo_header_len pbuf (Cstruct.lenv data);
      Tcpip_checksum.ones_complement_list (pbuf::data)

  let send_frame (port : port) bits =
    update_port_tx_stats (Int64.of_int (Cstruct.len bits)) port;
    return (port.out_push (Some bits))

  let forward_frame (st : t) (* it has controller *) in_port bits checksum port (* output port *)
			table cookie of_match = 
	let open SwMatch in
    let _ = 									(* XXX check *)
      if ((checksum) && ((get_dl_header_dl_type bits) = 0x800)) then 
        let ip_data = Cstruct.shift bits sizeof_dl_header in
        let len = (get_nw_header_hlen_version ip_data) land 0xf in 
        let _ = set_nw_header_csum ip_data 0 in
        let csm = Tcpip_checksum.ones_complement (Cstruct.sub ip_data 0 (len*4)) in
        let _ = set_nw_header_csum ip_data csm in
        let _ = 
          match (get_nw_header_nw_proto ip_data) with
          | 6 (* TCP *) -> 
              let src = Ipaddr.V4.of_int32 (get_nw_header_nw_src ip_data) in 
              let dst = Ipaddr.V4.of_int32 (get_nw_header_nw_dst ip_data) in 
              let tp_data = Cstruct.shift ip_data (len*4) in  
              let _ = set_tcpv4_checksum tp_data 0 in
              let csm = tcp_checksum ~src ~dst [tp_data] in 
                set_tcpv4_checksum tp_data csm  
          | 17 (* UDP *) -> ()
          | _ -> ()
        in
          () 
    in 
    match port with
    | PhysicalPort portId -> 
      if Hashtbl.mem st.int_to_port portId then
        let out_p = (!( Hashtbl.find st.int_to_port portId))  in
        send_frame out_p bits 
      else
        return (pp "[switch] forward_frame: Port %ld not registered\n%!" portId)
(*    | OP.Port.No_port -> return () *)			(* XXX check *)

    | InPort -> begin
	  match in_port with
	  | Some port ->
		  if Hashtbl.mem st.int_to_port port then
		    send_frame (!(Hashtbl.find st.int_to_port port))  bits
		  else
		    return (pp "[switch] forward_frame: Port %ld unregistered\n%!" port)
	  | None ->
			return (pp "[switch] forward_frame: Input port undefined!")
												(* XXX return error to the controller? *)
	  end

    | Flood (* XXX TODO VLAN *)
    | AllPorts ->
      Lwt_list.iter_p
        (fun (p : port) -> 
		  match in_port with
		  | Some port ->
			  if (p.port_id != port) then (* all ports except input port *) 
            	send_frame p bits
			  else 
             	return ()
		  | None -> send_frame p bits
        ) st.ports

    | Local ->
      let local = (PseudoPort.marshal Local) in 
      if Hashtbl.mem st.int_to_port local then
        send_frame !(Hashtbl.find st.int_to_port local) bits
      else 
        return (pp "[switch] forward_frame: Port %ld unregistered \n%!" local)

    | Controller c -> begin (* TODO c *)
       match st.controller with
       | None -> return ()
       | Some conn -> 
		  match in_port with
		  | Some port ->
			  let pkt_in = ({ pi_payload = NotBuffered bits
							; pi_total_len = Cstruct.len bits
							; pi_reason = ExplicitSend
							; pi_table_id = table
							; pi_cookie = cookie
							; pi_ofp_match = if of_match = [] then [OxmInPort port] else of_match
							}) 
							in
				let _ = pp "[switch] packet_in: %s\n" (PacketIn.to_string pkt_in) in
				OSK.send_packet conn (Message.marshal (Random.int32 Int32.max_int) (PacketInMsg pkt_in)) 
		  | None ->
			  return (pp "[switch] forward_frame: Input port undefined!") (* XXX return error to the controller? *)
       end 
        (*           | Table
         *           | Normal  *)
	| Table (* XXX TODO *)
	| Any (* XXX TODO *)
	| _ -> 
	  return (pp "[switch] forward_frame: unsupported output port\n")

  let set_field field bits checksum =
	(* XXX any check to see if set-field matches packet type? 
	 for isntance, OxmIP4Src has to apply to an IPv4 packet *)
	let open SwMatch in
	match field with
    | OxmEthSrc eaddr -> (* XXX mask is ignored. What is the case in manual? *)
      let _ = set_dl_header_dl_src (Int64.to_string eaddr.m_value) 0 bits in 
    	  return checksum
    | OxmEthDst eaddr ->
      let _ = set_dl_header_dl_dst (Int64.to_string eaddr.m_value) 0 bits in 
          return checksum 
  (* TODO: Add for this actions to check when inserted if 
    * the flow is an ip flow *)
    | OxmIPDscp dscp -> (* XXX TODO *)
      let ip_data = Cstruct.shift bits sizeof_dl_header in
      	let _ = set_nw_header_nw_tos ip_data dscp in
          return true 
  (* TODO: wHAT ABOUT ARP? *)
    | OxmIP4Src ip -> 
      let ip_data = Cstruct.shift bits sizeof_dl_header in
      	let _ = set_nw_header_nw_src ip_data ip.m_value in 
          return true 
    | OxmIP4Dst ip -> 
      let ip_data = Cstruct.shift bits sizeof_dl_header in
        let _ = set_nw_header_nw_dst ip_data ip.m_value in 
          return true 
    | OxmTCPSrc port 
	| OxmUDPSrc port ->
      let ip_data = Cstruct.shift bits sizeof_dl_header in
      let len = (get_nw_header_hlen_version ip_data) land 0xf in 
      let tp_data = Cstruct.shift ip_data (len*4) in
      let _ = set_tp_header_tp_src tp_data port in 
        return true 
    | OxmTCPDst port
	| OxmUDPDst port ->
      let ip_data = Cstruct.shift bits sizeof_dl_header in
      let len = (get_nw_header_hlen_version ip_data) land 0xf in 
      let tp_data = Cstruct.shift ip_data (len*4) in 
      let _ = set_tp_header_tp_dst tp_data port in 
        return true
    | act ->
      let _ = (pp "[switch] apply_of_actions: Unsupported set-fields %s" 
                        (Oxm.to_string act)) in (* XXX what happens if action doesn't exist at all? *)
          return checksum
  (*      | OP.Flow.Enqueue(_, _)
          | OP.Flow.Set_vlan_pcp _
          | OP.Flow.Set_vlan_vid _
          | OP.Flow.VENDOR_ACT 
          | OP.Flow.STRIP_VLAN *)

  (* Assume that action are valid. I will not get a flow that sets an ip
   * address unless it defines that the ethType is ip. Need to enforce
   * these rule in the parsing process of the flow_mod packets *)
  let apply_of_actions (st : t) in_port bits (actions : action list) 
			table cookie of_match =
	let open SwMatch in
    let apply_of_actions_inner (st : t) in_port bits checksum action =
      try_lwt
        match action with
        | Output port ->
          (* Make a packet copy in case the buffer is modified and multiple
           * outputs are defined? *)
          lwt _ = forward_frame st in_port bits checksum port table cookie of_match in 
          return false (* XXX check *)
		| SetField field -> set_field field bits checksum;
		| act ->
     	  	let _ = (pp "[switch] apply_of_actions: Unsupported set-fields %s" 
                       		(Action.to_string act)) in
			return false
      with exn -> 
        let _ = (pp  "[switch] apply_of_actions: (packet size %d) %s %s\n%!" 
                     (Cstruct.len bits) (Action.to_string action) 
                     (Printexc.to_string exn )) in
        return checksum 
    in
    let rec apply_of_actions_rec (st : t) in_port bits checksum = function
      | [] -> return false
      | head :: actions -> 
        lwt checksum = apply_of_actions_inner st in_port bits checksum head in
        apply_of_actions_rec st in_port bits checksum actions 
    in 
    lwt _ = apply_of_actions_rec st in_port bits false actions in 
    return ()


  let lookup_flow (table : Table.t) of_match =
  (* Check of_match first in table's cache.
   * If an exact match flow will be found on this step (an operation of O(1)), then 
   * return a result immediately, without needing to iterate through table's entries
   * and consider flow priorities *)
	if (Hashtbl.mem table.cache of_match) then
      let entry = (Hashtbl.find table.cache of_match) in
	  let _ = pp "exact match in table!\n" in
     	Found(of_match, entry) 
	else begin
     (* Check the wilcard card table *)
	  let lookup_flow flow entry r =
		match (r, SwMatch.check_flow_overlap of_match flow) with
		| (_, false) -> r
		| (None, true) -> Some(flow, entry)
		| (Some(f,e), true) when (Entry.(e.counters.priority > entry.counters.priority)) -> r
		| (Some(f,e), true) when (Entry.(e.counters.priority <= entry.counters.priority)) -> 
		   Some(flow, entry)
		| (_, _) -> r
		in
		let flow_match = Hashtbl.fold lookup_flow table.entries None in
		  match (flow_match) with
		  | None ->  NOT_FOUND
		  | Some(f,e) ->
		    Hashtbl.add table.cache of_match (ref e);
		    Entry.(e.cache_entries <- of_match :: e.cache_entries); 
		  	  Found (f, ref e)
	end


  let create_tcp_connection tcp (contaddr, contport) =
	T.create_connection tcp (Ipaddr.V4.of_string_exn contaddr, contport)
	>>= function 
		  | `Error e -> fail (Failure "[Swicth] failed connecting to the controller")
		  | `Ok fl -> (return fl)  (* returns flow *)

  let process_frame st (p : port) frame =
	if !hello_sent then (* Frenetic throws exception if packet_in is sent before hello *)
	  let _ = p.pkt_count <- p.pkt_count + 1 in
    	p.in_push (Some frame);
		return ()
	else
		return ()

  let init_switch_info ?(verbose=true) dpid = 
	{ (* dev_to_port=(Hashtbl.create 64); *)
	int_to_port = (Hashtbl.create 64); ports = [];
	controller=None;
	last_echo_req=0.; echo_resp_received=true;
	stats= {n_frags=0L; n_hits=0L; n_missed=0L; n_lost=0L;};
	errornum = 0l; portnum=0l;
	table = Table.init_tables 0; (* XXX we create a single table at the moment *)
	features'=(switch_features dpid); 
	packet_buffer=[]; packet_buffer_id=0l; ready=(Lwt_condition.create ());
	verbose; pkt_len=1500;}

(* add port to the switch *) 
  let add_port ?(use_mac=false) (sw : t) ethif = 

	sw.portnum <- Int32.add sw.portnum 1l;
	let hw_addr =  Macaddr.to_string (E.mac ethif) in
	(* let dev_name = N.id (E.id ethif) in *) (* TODO : how to extract dev_name? *)
	let _ = pp "[switch] Adding port %ld '%s' \n%!" 
								sw.portnum hw_addr in
	let port = init_port sw.portnum ethif in 
	  sw.ports <- sw.ports @ [port]; 
	  Hashtbl.add sw.int_to_port sw.portnum (ref port); 
	  let _ = N.listen (E.id ethif) (process_frame sw port) in 
	  match sw.controller with
		| None -> return ()
		| Some t -> OSK.send_packet t 
			(Message.marshal (Random.int32 Int32.max_int) (PortStatusMsg {reason = PortAdd; desc = port.phy}))
  
  let get_flow_stats (table : Table.t) (dflow : OfpMatch.t) out_port out_grp cookie =
	let match_flows of_match flow ret =
	  if (SwMatch.check_flow_overlap of_match dflow && 
		  ( (out_port = 0xffffl (* OFPP_ANY *)) || 
			(is_output_port out_port flow.Entry.instructions)
		  ) &&
		  ( (out_grp = 0xffffffffl (* OFPG_ANY *)) || 
			(is_output_group out_grp flow.Entry.instructions)
		  ) &&
		  ( let fcookie = flow.Entry.counters.cookie in
			(cookie.m_mask = Some 0L (* no restriction - manual 7.3.5.2 *)) || 
			(fcookie.m_mask = Some 0L (* XXX no restriction on flow cookie *)) || 
			( match fcookie.m_mask, cookie.m_mask with
			  | None, None -> fcookie.m_value = cookie.m_value
			  | Some fm, Some m -> 
				  (Int64.logand fcookie.m_value fm) = (Int64.logand cookie.m_value m)
			  | _, _ -> false (* XXX Important, it is wrong, figure the right tech *)
			)
		  ) 
		 ) then ( 
	  (Entry.flow_counters_to_flow_stats of_match (1) flow)::ret  (* XXX check (1)? *)
	  ) else 
        ret 
	in
	  Hashtbl.fold (fun of_match flow ret -> match_flows of_match flow ret) 
	  table.entries []  


  let get_aggr_stats (tables : Table.t list) (dflow : OfpMatch.t) out_port out_grp cookie =
	let match_flows of_match flow (fl_b, fl_p, fl) =
	  if (SwMatch.check_flow_overlap of_match dflow && 
		  ( (out_port = 0xffffl (* OFPP_ANY *)) || 
			(is_output_port out_port flow.Entry.instructions)
		  ) &&
		  ( (out_grp = 0xffffffffl (* OFPG_ANY *)) || 
			(is_output_group out_grp flow.Entry.instructions)
		  ) &&
		  ( let fcookie = flow.Entry.counters.cookie in
			(cookie.m_mask = Some 0L  (* no restriction - 1.4 manual 7.3.5.2 *)) || 
			(fcookie.m_mask = Some 0L (* XXX no restriction on flow cookie *)) || 
			( match fcookie.m_mask, cookie.m_mask with
			  | None, None -> fcookie.m_value = cookie.m_value
			  | Some fm, Some m -> 
				  (Int64.logand fcookie.m_value fm) = (Int64.logand cookie.m_value m)
			  | _, _ -> false (* XXX Important, wrong! figure the right tech *)
			)
		  ) 
		 )
	  then (Int64.add fl_b flow.counters.n_bytes, Int64.add fl_p flow.counters.n_packets, Int32.succ fl)
	  else (fl_b, fl_p, fl)
	in
	  let rec get_aggr_stats_r tables aggr =
		match tables with
		| [] -> aggr
		| h::t -> let r = 
			Hashtbl.fold (fun of_match flow ret -> match_flows of_match flow ret) h.Table.entries aggr in  
			get_aggr_stats_r t r
	  in
		get_aggr_stats_r tables (0L, 0L, 0l)

(* called when a packet is buffered --
   buffering applies to missed packet for this implementation
*)
  let process_buffer_id (st : t) conn msg xid buffer_id port_in actions = (* XXX check correct functionality *)
	let pkt_in = ref None in
	let _ = 
	  st.packet_buffer <-
		List.filter ( fun (id, frame) -> 
		if (id = buffer_id) then
    	  (pkt_in := Some frame; false )
		else true
		) st.packet_buffer in 
		  match (!pkt_in) with 
		  | None ->
			  pp "[switch] invalid buffer id %ld\n%!" buffer_id; 
			  OSK.send_packet conn (Message.marshal xid (Error {err = BadRequest ReqBufferUnknown; data = msg}))
		  | Some frame ->
			  let (table_id, cookie, of_match) = (0, -1L, []) in
			  apply_of_actions st port_in msg actions table_id cookie of_match
	
  let process_openflow (st : t) conn (xid, msg) =
	let open Message in

	let _ = if st.verbose then pp "[switch] %s\n%!" (Message.to_string msg) in

	match msg with
	| Hello buf -> return () 					(* TODO: check version *)
	| EchoRequest buf -> 						(* Reply to ECHO requests *)
		OSK.send_packet conn (Message.marshal xid msg) 
	| EchoReply buf -> return (st.echo_resp_received <- true) 
	| FeaturesRequest  -> 
		OSK.send_packet conn (Message.marshal xid (FeaturesReply st.features'))

	| MultipartReq {mpr_type = req; mpr_flags = flag } ->
	  begin (* MultipartReq *)
		match req with
		  | SwitchDescReq ->
			let p = SwitchDescReply { mfr_desc = "Mirage"
					; hw_desc = "Mirage"
					; sw_desc = "Mirage"
					; serial_num = "0.1" } in
			let rep = {mpreply_typ = p; mpreply_flags = false} in (* XXX check flag *)
	 		  OSK.send_packet conn (Message.marshal xid (MultipartReply rep)) 
		  | PortsDescReq ->
			let stats = PortsDescReply (List.map (fun x -> x.phy) st.ports) in
			let rep = {mpreply_typ = stats; mpreply_flags = false} in (* XXX check flag *)
 			  OSK.send_packet conn (Message.marshal xid (MultipartReply rep))

		  | FlowStatsReq 
				{ fr_table_id = table_id; fr_out_port = port
				; fr_out_group = gport; fr_cookie = fcookie
				; fr_match = of_match} ->
			begin
			  let rec add_flow_stats tables =
				match tables with
				| [] -> []
				| h::t -> (get_flow_stats h of_match port gport fcookie) @ (add_flow_stats t)
			  in
			  try
			  	let table_list =
				  match table_id with
		 		  | 0xff -> st.table (* OFPTT_ALL *)
				  | t -> 
					  [ List.find (fun x -> x.Table.tid = t) st.table ] (* single table *)
			  	in
				let fls = add_flow_stats table_list in
				  lwt flows = 
					Lwt_list. fold_right_s (
					  fun fl flows ->
						let reply = { mpreply_typ = FlowStatsReply (fl::flows)
							  		; mpreply_flags = true} in 
						let fl_sz = MultipartReply.sizeof reply in
						  if (OpenFlow_Header.size + fl_sz > 0xffff (* 64KB limit *)) then 
						  	let rep = { mpreply_typ = FlowStatsReply flows
							  		  ; mpreply_flags = true} in (* more reply will come *)
				  			let _ = OSK.send_packet conn (Message.marshal xid (MultipartReply rep)) in
							return [fl]
						  else
							return (fl::flows) )
					fls [] 
					in
					let rep = { mpreply_typ = FlowStatsReply flows
							  ; mpreply_flags = false} in
					OSK.send_packet conn (Message.marshal xid (MultipartReply rep))

			  with Not_found ->
				pp "[switch] invalid table id (%d) in flow stats request\n%!" table_id;
				OSK.send_packet conn (Message.marshal xid (Error { err = BadRequest ReqBadTableId
															  ; data = Cstruct.create 0}))
			end

		  | AggregFlowStatsReq
				{ fr_table_id = table_id; fr_out_port = port
				; fr_out_group = gport; fr_cookie = fcookie
				; fr_match = of_match} ->
			begin
			  try
			  	let table_list =
				  match table_id with
		 		  | 0xff -> st.table (* OFPTT_ALL *)
				  | t -> 
					  [ List.find (fun x -> x.Table.tid = t) st.table ] (* single table *)
			  	in
				  let (byte_count, packet_count, flow_count) = 
					get_aggr_stats table_list of_match port gport fcookie in
				  let stats = { packet_count; byte_count; flow_count} in
				  let rep = { mpreply_typ = AggregateReply stats
							; mpreply_flags = false} in
				  OSK.send_packet conn (Message.marshal xid (MultipartReply rep))

			  with Not_found ->
				pp "[switch] invalid table id (%d) in flow stats request\n%!" table_id;
				OSK.send_packet conn (Message.marshal xid (Error { err = BadRequest ReqBadTableId
															  ; data = Cstruct.create 0}))
			end

		  | TableStatsReq -> (* XXX 64KB restriction required? *)
			let tstats = List.map (fun t -> 
					{ table_id = t.Table.tid
					; active_count = t.Table.counter.n_active
					; lookup_count = t.Table.counter.n_lookups
					; matched_count = t.Table.counter.n_matches}) st.table in
				let rep = { mpreply_typ = TableReply tstats
						  ; mpreply_flags = false} in
				OSK.send_packet conn (Message.marshal xid (MultipartReply rep))
				
		  | PortStatsReq port -> (* XXX 64KB restriction required? *)
			let stats = PortStatsReply (List.map (fun x -> x.counter) st.ports) in
			let rep = {mpreply_typ = stats; mpreply_flags = false} in
	 		  OSK.send_packet conn (Message.marshal xid (MultipartReply rep)) 
	(* XXX TODO
		  | QueueStatsReq of queueRequest
		  | GroupStatsReq of int32
		  | GroupDescReq
		  | GroupFeatReq
		  | MeterStatsReq of int32
		  | MeterConfReq of int32
		  | MeterFeatReq
		  | TableFeatReq of (tableFeatures list) option
		  | ExperimentReq of experimenter  
	*)
		  | _ -> 
			OSK.send_packet conn (Message.marshal xid (Error { err = BadRequest ReqBadMultipart
														  ; data = Cstruct.create 0}))
	end (* MultipartReq *)

	| FlowModMsg fm -> 							(* TODO: Careful revision of add/mod/strict *)
	  lwt _ = 
	    match fm.mfCommand with
	      | AddFlow | ModFlow | ModStrictFlow ->
			begin
			try
			  let table = List.find (fun x -> x.Table.tid = fm.mfTable_id) st.table in
				Table.add_flow table fm conn st.verbose
			with Not_found ->
			  pp "[switch] invalid table id (%d) in flow mod (add/mod) request\n%!" fm.mfTable_id;
			  OSK.send_packet conn (Message.marshal xid (Error { err = BadRequest ReqBadTableId
															  ; data = Cstruct.create 0}))
			end
	 
	      | DeleteFlow | DeleteStrictFlow ->	(* TODO: Careful revision of del/strict *)
	        (* Need to implemente strict deletion in order to enable signpost
	         * switching *)
			begin
			try
			  let table = List.find (fun x -> x.Table.tid = fm.mfTable_id) st.table in
				Table.del_flow table fm.mfOfp_match fm.mfOut_port (Some conn) st.verbose
			with Not_found ->
			  pp "[switch] invalid table id (%d) in flow mod (add/mod) request\n%!" fm.mfTable_id;
			  OSK.send_packet conn (Message.marshal xid (Error { err = BadRequest ReqBadTableId
															  ; data = Cstruct.create 0}))
			end
	  in
		return ()

	| GetConfigRequestMsg ->
		OSK.send_packet conn (Message.marshal xid (GetConfigReplyMsg { flags = NormalFrag; miss_send_len = st.pkt_len}))
				(* XXX check it *)

	| BarrierRequest ->
		OSK.send_packet conn (Message.marshal xid (BarrierReply))

	| PacketOutMsg pkt -> 
		begin
		  match pkt.po_payload with 
			| NotBuffered p -> apply_of_actions st pkt.po_port_id p pkt.po_actions 0 0L [] (* XXX cookie -1L? *)
			| Buffered (n, p) -> process_buffer_id st conn p xid n pkt.po_port_id pkt.po_actions 
		end 

	| SetConfigMsg msg -> 
		(* use miss_send_len when sending a pkt_in message*)
		let _ = st.pkt_len <- msg.miss_send_len in
		  return ()
	(*												(* TODO *)
	  | BarrierReply
	  | StatsReplyMsg _
	  | PortStatusMsg _
	  | FlowRemovedMsg _
	  | PacketInMsg _
	  | ConfigReplyMsg _
	  | SwitchFeaturesReply _
	  | VendorMsg _
	  | ErrorMsg _ ->
	*)
	| _ ->
	  OSK.send_packet conn (Message.marshal xid (Error {err = BadRequest ReqBadType; data = Cstruct.create 0}))

(* end of process_openflow *)

(*************************************************
 * Switch OpenFlow control channel 
 *************************************************)

  let monitor_control_channel (sw : t) conn =
	let is_active = ref true in 
  	while_lwt !is_active do
      let _ = sw.echo_resp_received <- false in 
      let _ = sw.last_echo_req <- (Clock.time ()) in 
      lwt _ = OSK.send_packet conn (Message.marshal 1l (EchoRequest (Cstruct.create 0))) in (* XXX check xid *)
		lwt _ = OS.Time.sleep 10.0 in 
		return (is_active := sw.echo_resp_received) 
	done 

  let control_channel_run (st : t) conn = 
	let _ = OSK.send_packet conn (Message.marshal 1l (Hello [VersionBitMap [0x20]])) in (* XXX check xid *)
	let _ = hello_sent := true in

	let rec echo () =
	  try_lwt
		OSK.read_packet conn >>= 
		fun msg -> process_openflow st conn msg >> echo ()
	  with
		| Unparsed (m, bs) ->
		  pp "[switch] ERROR:unparsed! m=%s\n %!" m; echo ()
		| exn ->
		  return (pp "[switch] ERROR:%s\n%!" (Printexc.to_string exn)) (* ; echo () *)
	  in
	  lwt _ = 
		echo () <?> 
		(Table.monitor_flow_timeout st.table (Some conn) st.verbose) <?>
		(monitor_control_channel st conn)
	  in 
	  let _ = OSK.close conn in 
		return (pp "[switch] control channel thread returned\n") (* TODO: terminate switch operation *)


  (*********************************************
   * Switch OpenFlow data plane 
   *********************************************)

let rec table_lookup st table frame_match frame port_id action_set =
  let order_instructions inst =
	(List.filter (fun x -> match x with | Meter _ -> true | _ -> false) inst) @
	(List.filter (fun x -> match x with | ApplyActions _ -> true | _ -> false) inst) @
	(List.filter (fun x -> match x with | Clear _ -> true | _ -> false) inst) @
	(List.filter (fun x -> match x with | WriteActions _ -> true | _ -> false) inst) @
	(List.filter (fun x -> match x with | WriteMetadata _ -> true | _ -> false) inst) @
	(List.filter (fun x -> match x with | GotoTable _ -> true | _ -> false) inst)
  in
  let modify_act_set wr_act act_set =
	let act_to_num a =
	match a with
    | CopyTtlIn -> 0	| PopVlan -> 1	| PopMpls -> 2	| PopPbb ->	3	| PushMpls -> 4
    | PushPbb -> 5		| PushVlan -> 6	| CopyTtlOut-> 7| DecNwTtl -> 8	| DecMplsTtl -> 9
    | SetField _ -> 10	| SetNwTtl _ -> 11
	| SetMplsTtl _ -> 12| SetQueue _ ->	13
    | Group _ -> 14		| Output _ -> 15
    (* | Experimenter _ -> 16 *) 				(* XXX check experimenter *)
	in
	let rec unique = function
	| [] -> []
	| e1 :: e2 :: tl when act_to_num e1 = act_to_num e2 -> e1 :: unique tl
	| hd :: tl -> hd :: unique tl
	in
	let al = wr_act @ act_set in (* order preserved *)
	  unique (List.stable_sort (fun x y -> (act_to_num x) - (act_to_num y)) al)
  in
  let apply_of_instructions (st : t) bits table (of_match, entry) action_set =
	let cookie = (!entry).Entry.counters.cookie.m_value in
	let _ = Entry.update_flow (Int64.of_int (Cstruct.len bits)) !entry in
	let open SwMatch in
    let rec apply_of_instructions_rec (st : t) bits checksum act_set inst =
	  try_lwt
	  match inst with
      | [] ->						(* there is no Goto, execute action_set *)
			apply_of_actions st (Some port_id) bits act_set table.Table.tid cookie of_match
	  | Clear :: instructions ->	(* clears action_set *)
			apply_of_instructions_rec st bits checksum [] instructions
	  | WriteActions wr_act :: instructions ->
			let new_act_set = modify_act_set wr_act act_set in
			apply_of_instructions_rec st bits checksum new_act_set instructions
	  | ApplyActions acts :: instructions ->
			apply_of_actions st (Some port_id) bits acts table.Table.tid cookie of_match 
	  | GotoTable tid :: instructions -> 
			let next_table = List.nth st.table tid in
			if (next_table.Table.tid > table.Table.tid) then
			  table_lookup st (List.nth st.table tid) frame_match frame port_id action_set
			else
			  return (pp "[switch] apply_of_instructions: Goto table id <= table id %d" 
                       		next_table.Table.tid) 
	  | i :: instructions ->
      	return (pp "[switch] apply_of_instructions: Unsupported instruction %s" 
                       		(Instruction.to_string i))
	  
      with exn -> 
        return (pp  "[switch] apply_of_instructions: (packet size %d) %s %s\n%!" 
                     (Cstruct.len bits) (Instruction.to_string (List.hd inst)) 
                     (Printexc.to_string exn ))
    in 
    lwt _ = apply_of_instructions_rec st bits false action_set (order_instructions (!entry).instructions) in 
    return ()
  in
  (* Lookup packet flow to existing flows in table *)
  match  (lookup_flow table frame_match) with	
  | NOT_FOUND -> begin							(* TODO: table-miss to implement *)
	let _ = print_endline "table miss..." in
	(* Table.update_table_missed st.table; *)
	let buffer_id = st.packet_buffer_id in
	  st.packet_buffer_id <- Int32.add st.packet_buffer_id 1l;
	  (* XXX what happens if packet_buffer_id overloads? *)
	  st.packet_buffer <- (buffer_id, frame)::st.packet_buffer; 
	  let size =
		if (Cstruct.len frame > 92) then 92		(* XXX check 92 *)
		else Cstruct.len frame in
		  let pkt_in = ({ pi_total_len = Cstruct.len frame
						; pi_reason = ExplicitSend
						; pi_table_id = table.tid
						; pi_cookie = 0L
						; pi_ofp_match = [OxmInPort port_id]
						; pi_payload = Buffered (buffer_id, Cstruct.sub frame 0 size)
						}) in
			return (
			  match st.controller with
			  | None -> pp "[switch] controller not set."
			  | Some conn ->
				let _ = pp "[switch*] packet_in: %s\n" (PacketIn.to_string pkt_in) in
					ignore_result 
					(OSK.send_packet conn (Message.marshal (Random.int32 Int32.max_int) (PacketInMsg pkt_in)))
			)
    end (* switch not found*)
  | Found (of_match, entry) -> 					(* XXX not buffer? *)
	let _ = pp "entry found: %s\n Instructions: %s\n"
				(OfpMatch.to_string of_match) (Instructions.to_string (!entry).instructions) in
	  (* TODo: let _ = Table.update_table_found st.table in *)
	  apply_of_instructions st frame table (of_match, entry) action_set


(* in checking progress ... *)
  let process_frame_inner (st : t) (p : port) frame =
  	try_lwt
      let port_id = p.port_id in 
      let frame_match = (SwMatch.raw_packet_to_match port_id frame)  in 
	  (* Update port rx statistics *)
	  let _ = update_port_rx_stats (Int64.of_int (Cstruct.len frame)) p in
	  let _ = print_endline "lookup frame:" in
		table_lookup st (List.hd st.table) frame_match frame port_id []
	with exn ->
	  return (pp "[switch] process_frame_inner: control channel error: %s\n" 
       	(Printexc.to_string exn))


  (* Swicth port input/output operation *)
  let forward_thread (st : t) =
	Lwt_list.iter_p (fun (p : port) -> 
	  while_lwt true do
        lwt _ = Lwt_stream.next p.in_queue >>= process_frame_inner st p in
        return (p.pkt_count <- p.pkt_count - 1)  (* XXX why packet_count is subtracted by 1? *)
	  done  <&> (
	  while_lwt true do
		lwt frame = Lwt_stream.next p.out_queue in
		E.write p.ethif frame
	  done
	  )
    ) st.ports


  let rec add_switch_ports sw ethlist =
	match ethlist with
	  | [] -> return ()
	  | eth::t -> add_port sw eth >> add_switch_ports sw t


  let create_switch tcp cont ethlist =
	let rec connect_socket () =
	  let sock = ref None in 
		try_lwt
		  let _ = pp "connecting to the remote controller...\n%!" in 
			lwt _ = Lwt.pick
			    [create_tcp_connection tcp cont >>= (fun t -> return (sock:= Some t));
			     (OS.Time.sleep 10.0)]
		  in
			match !sock with
			| None -> connect_socket ()
			| Some t -> return t 
		with exn -> connect_socket ()
	in
	  let sw = init_switch_info 0x100L (* model *) in
		(* TODO1: move 'verbose' and 'dpid' to the unikernel. Check if to choose a rand for dpid *)
		lwt _ = add_switch_ports sw ethlist in
		connect_socket ()
		>>= fun fl -> 
			let conn = OSK.init_socket_conn_state (OSK.create fl)
			  in
				let _ = sw.controller <- (Some conn) in 
				lwt _ = ((control_channel_run sw conn) <&> (forward_thread sw) ) in 
				let _ = OSK.close conn in 
      			  return (pp "[switch] Disconnected from remote controller.\n")


end (* end of Switch module *)
