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

open OpenFlow0x01
open OpenFlow0x01_Core
open OpenFlow0x01_Stats

module Message = OpenFlow0x01.Message

exception Packet_type_unknw
exception Unparsable of string * Cstruct.t 
exception Unparsed of string * Cstruct.t 
exception Unsupported of string 

let sp = Printf.sprintf
let pp = Printf.printf
let ep = Printf.eprintf

type cookie = int64

let resolve t = Lwt.on_success t (fun _ -> ())

let get_new_buffer len = 
  let buf = Io_page.to_cstruct (Io_page.get 1) in 
    Cstruct.sub buf 0 len 

(* XXX check possible replacement *)
let or_error name fn t =
  fn t
  >>= function
	| `Error e -> fail (Failure ("Error starting " ^ name))
    | `Ok t -> let _ = (pp "%s works...\n" name) in
			   return t

module Entry = struct

  type table_counter = {
    n_active: int32;
    n_lookups: int64;
    n_matches: int64;
  }

  type flow_counter = {
    mutable n_packets: int64;
    mutable n_bytes: int64;
    flags : int16; (* OP.Flow_mod.flags;  *)
    priority: int16;
    cookie: int64;
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

  (* XXX where is EMERG? *)
  let flags_to_int (check_overlap : bool) (notify_when_removed : bool) =
    (if check_overlap then 1 lsl 1 else 0) lor
      (if notify_when_removed then 1 lsl 0 else 0)

  let check_overlap_of_flags flags = 
    (1 lsl 1) land flags != 0

  let notify_when_removed_of_flags flags = 
    (1 lsl 0) land flags != 0

  let init_flow_counters (t : FlowMod.t) =
    let ts = int_of_float (Clock.time ()) in
    ({n_packets=0L; n_bytes=0L; priority=t.priority; 
	cookie=t.cookie; insert_sec=ts; insert_nsec=0; 
	last_sec=ts;last_nsec=0; idle_timeout=t.idle_timeout; 
    hard_timeout=t.hard_timeout; flags=(flags_to_int (t.check_overlap) (t.notify_when_removed)); })

  (* flow table *)
  type t = { 
    counters: flow_counter;
    actions: Action.t list;
    mutable cache_entries: Match.t list; (* eq to header fields in manual *)
  }

  let update_flow pkt_len flow = 
    flow.counters.n_packets <- Int64.add flow.counters.n_packets 1L;
    flow.counters.n_bytes <- Int64.add flow.counters.n_bytes pkt_len;
    flow.counters.last_sec <- int_of_float (Clock.time ())

  let flow_counters_to_flow_stats of_match table_id flow = (* return type: individualStats *)
    let priority = flow.counters.priority in
    let idle_timeout=flow.counters.idle_timeout in
    let hard_timeout=flow.counters.hard_timeout in
    let cookie=flow.counters.cookie in
    let packet_count=flow.counters.n_packets in 
    let byte_count=flow.counters.n_bytes in
    let actions=flow.actions in
    ({table_id; of_match; 
    duration_sec = Int32.of_int (flow.counters.last_sec -
    flow.counters.insert_sec);
    duration_nsec = Int32.of_int (flow.counters.last_nsec -
    flow.counters.insert_nsec);
    priority;
	idle_timeout = (Timeout.to_int idle_timeout);
	hard_timeout = (Timeout.to_int hard_timeout);
	cookie;
    packet_count; byte_count; actions; })

end

module SMatch = struct

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

  cstruct tp_header {
    uint16_t tp_src;
    uint16_t tp_dst
  } as big_endian 

  cstruct icmphdr {
    uint8_t typ;
    uint8_t code;
    uint16_t checksum
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


  let raw_packet_to_match in_port bits = 
    let dlDst = Some (Packet.mac_of_bytes (Cstruct.to_string (get_dl_header_dl_dst bits))) in
    let dlSrc = Some (Packet.mac_of_bytes (Cstruct.to_string (get_dl_header_dl_src bits))) in
    let dl_type = get_dl_header_dl_type bits in
    let bits = Cstruct.shift bits sizeof_dl_header in 

    match (dl_type) with 
    | 0x0800 -> begin
      let nw_src = get_nw_header_nw_src bits in 
      let nw_dst = get_nw_header_nw_dst bits in 
      let nw_proto = get_nw_header_nw_proto bits in 
      let nw_tos = get_nw_header_nw_tos bits in 
      let len = (get_nw_header_hlen_version bits) land 0xf in 
      let bits = Cstruct.shift bits (len*4) in
	  let tpSrc, tpDst =
        match (nw_proto) with
        | 17 
        | 6 -> Some (get_tp_header_tp_src bits), Some (get_tp_header_tp_dst bits)
        | 1 -> Some (get_icmphdr_typ bits), Some (get_icmphdr_code bits)
        | _ -> Some 0, Some 0
		in
			OpenFlow0x01_Core.({ 
			  dlSrc; dlDst
			; dlTyp = Some dl_type
			; dlVlan = Some (Some 0xffff) (* XXX send to Frenetic mailing list? *)
			; dlVlanPcp = Some 0
			; nwSrc = Some { m_value = nw_src; m_mask = None}
			; nwDst = Some { m_value = nw_dst; m_mask = None}
			; nwProto = Some nw_proto
			; nwTos = Some nw_tos
			; tpSrc
			; tpDst
			; inPort = Some in_port })
      end 
    | 0x0806 ->
      let nw_src = get_nw_header_nw_src bits in 
      let nw_dst = get_nw_header_nw_dst bits in 
		OpenFlow0x01_Core.({ 
		  dlSrc; dlDst
		; dlTyp = Some dl_type
		; dlVlan = Some (Some 0xffff)
		; dlVlanPcp = Some 0
		; nwSrc = Some { m_value = nw_src; m_mask = None}
		; nwDst = Some { m_value = nw_dst; m_mask = None}
		; nwProto = Some (get_arphdr_ar_op bits)
		; nwTos = Some 0
		; tpSrc = Some 0
		; tpDst = Some 0
		; inPort = Some in_port })
    | _ ->  
		OpenFlow0x01_Core.({ 
		  dlSrc; dlDst
		; dlTyp = Some dl_type
		; dlVlan = Some (Some 0xffff)
		; dlVlanPcp = None
		; nwSrc = Some { m_value = Int32.of_int 0; m_mask = None}
		; nwDst = Some { m_value = Int32.of_int 0; m_mask = None}
		; nwProto = None
		; nwTos = Some 0
		; tpSrc = Some 0
		; tpDst = Some 0
		; inPort = Some in_port })

  let flow_match_compare (flow : OpenFlow0x01.Match.t) (flow_patten : OpenFlow0x01.Match.t) =
    let matches f f_pattern = match f, f_pattern with
	  | _, None -> true
      | Some x, Some y -> x = y
      | _, _ -> false
	in
	(matches flow.inPort flow_patten.inPort) &&
	(matches flow.dlSrc flow_patten.dlSrc) && (matches flow.dlDst flow_patten.dlDst) &&
	(matches flow.dlTyp flow_patten.dlTyp) &&
	(matches flow.nwProto flow_patten.nwProto) &&
	(matches flow.tpSrc flow_patten.tpSrc) && (matches flow.tpDst flow_patten.tpDst) &&
	(matches flow.nwTos flow_patten.nwTos) &&
	(matches flow.dlVlanPcp flow_patten.dlVlanPcp)  &&
	(matches flow.dlVlan flow_patten.dlVlan) (* XXX check,dlvlan is of type option option vid *) &&
	( match flow.nwSrc, flow_patten.nwSrc with
		| _, None -> true
		| Some {m_value = f; _} , Some {m_value = f_p; m_mask = None} -> f = f_p
		| Some {m_value = f; _} , Some {m_value = f_p; m_mask = Some m} ->
		    (Int32.shift_right_logical f (Int32.to_int m)) = (Int32.shift_right_logical f_p (Int32.to_int m))
		| _, _ -> false
	) &&
	( match flow.nwDst, flow_patten.nwDst with
		| _, None -> true
		| Some {m_value = f; _} , Some {m_value = f_p; m_mask = None} -> f = f_p
		| Some {m_value = f; _} , Some {m_value = f_p; m_mask = Some m} ->
		    (Int32.shift_right_logical f (Int32.to_int m)) = (Int32.shift_right_logical f_p (Int32.to_int m))
		| _, _ -> false
	)
(*
  let wildcards_of_match (m : Match.t) : Wildcards.t =
	let open OF in
	let open OF_Core in

	let is_none x = match x with
	| None -> true
    | Some _ -> false
	in  
	  let mask_bits x = match x with
	  | None -> 32 (* WildcardAll *)
	  | Some x -> match x.m_mask with
                  | None -> 0 (* WildcardExact *)
                  | Some m -> Int32.to_int m
	  in
	  { Wildcards.in_port = is_none m.inPort;
		Wildcards.dl_vlan = 
		(match m.dlVlan with 
		  | None -> true
		  | Some None -> false
		  | Some (Some _) -> false);
		Wildcards.dl_src = is_none m.dlSrc;
		Wildcards.dl_dst = is_none m.dlDst;
		Wildcards.dl_type = is_none m.dlTyp;
		Wildcards.nw_proto = is_none m.nwProto;
		Wildcards.tp_src = is_none m.tpSrc;
		Wildcards.tp_dst = is_none m.tpDst;
		Wildcards.nw_src = mask_bits m.nwSrc;
		Wildcards.nw_dst = mask_bits m.nwDst;
		Wildcards.dl_vlan_pcp = is_none m.dlVlanPcp;
		Wildcards.nw_tos = is_none m.nwTos;
	  } 
*)
end

module Make(T:TCPV4 (* controller *))(N:NETWORK) = struct

  module E = Ethif.Make(N)
  module Channel = Channel.Make(T)
  module OSK = Ofsocket0x01.Make(T)

  type eth_t = E.t 

  type port_stats = {
	mutable port_id : int16;
	mutable rx_packets : int64;
	mutable tx_packets : int64;
	mutable rx_bytes : int64;
	mutable tx_bytes : int64;
	mutable rx_dropped : int64;
	mutable tx_dropped : int64;
	mutable rx_errors : int64;
	mutable tx_errors : int64;
	mutable rx_frame_err : int64;
	mutable rx_over_err : int64;
	mutable rx_crc_err : int64;
	mutable collisions : int64;
  }

  type port = {
    port_id: portId;
    ethif: E.t;
    port_name: string;
    counter: port_stats;
    phy': PortDescription.t;
    in_queue: Cstruct.t Lwt_stream.t;
    in_push : (Cstruct.t option -> unit);
    out_queue: Cstruct.t Lwt_stream.t;
    out_push : (Cstruct.t option -> unit);
    mutable pkt_count : int;
  }

  module Table = struct
	type t = {
	  tid: cookie; (* XXX why we have cookie in both table and entry module? Do we need it for Table? *)

	  (* This entry stores wildcard and exact match entries as
	   * transmitted by the controller *)

	  (* XXX each entry contains a list of header fields. Why we have one per entry here? *)
	  mutable entries: (Match.t, Entry.t) Hashtbl.t;

	  (* Intermediate table to store exact match flows deriving from wildcard
	   * entries *)

	  (* XXX each entry contains a list of header fields. Why we have one per entry here? *)
	  mutable cache : (Match.t, Entry.t ref) Hashtbl.t;
	  (* stats : OP.Stats.table; *) (* removed for now *)
	}

	let init_table () = 
		{ tid = 0_L; entries = (Hashtbl.create 10000); cache = (Hashtbl.create 10000);
		(* stats = OP.Stats.(
		  {table_id=(OP.Stats.table_id_of_int 1); name="main_tbl"; 
		  wildcards=(OP.Wildcards.exact_match ()); max_entries=1024l; active_count=0l; 
		  lookup_count=0L; matched_count=0L});*)}

	(* TODO fix flow_mod flag support. overlap is not considered *)
	(* XXX st as argument is never used in Table functions *)
	let add_flow st table (fm : flowMod) verbose =
		(* TODO check if the details are correct e.g. IP type etc. *)
		let priority =
		  (* max priority for exact match rules *)
		  (* if  ((wildcards_of_match t) ={
    in_port = false; dl_vlan: false; dl_src: false; dl_dst: false; dl_type: false; nw_proto: false;
    tp_src: false; tp_dst: false; nw_src: 0; nw_dst: 0; dl_vlan_pcp: false; nw_tos: false;}) then *)
		    0x1001 (* XXX important: check it *)
		in
		let entry = Entry.({actions=fm.actions; counters=(init_flow_counters fm); 
		         cache_entries=[];}) in  
		let _ = Hashtbl.replace table.entries fm.pattern entry in
		(* In the fast path table, I need to delete any conflicting entries *)
		let _ = 
		  Hashtbl.iter (
		    fun a e -> 
		      if ((SMatch.flow_match_compare a fm.pattern) && 
		          Entry.(entry.counters.priority >= (!e).counters.priority)) then ( 
		            let _ = (!e).Entry.cache_entries <- 
		              List.filter (fun c -> a <> c) (!e).Entry.cache_entries in 
		            let _ = Hashtbl.replace table.cache a (ref entry) in 
		              entry.Entry.cache_entries <- a :: entry.Entry.cache_entries
		          )
		  ) table.cache in
		let _ = if (verbose) then 
		  pp "[switch] Adding flow %s\n" (Match.to_string fm.pattern)
		in
		  return ()

	  (* check if a list of actions has an output action forwarding packets to
	   * out_port.
	   * Used when removing a port from the switch control in order to clean related
	   * flows *)

  let rec is_output_port out_port = function
	| [] -> false
	| Output (PhysicalPort portId) ::_ when (portId = out_port) -> true
	| head::tail -> is_output_port out_port tail 


  let marshal_optional t = match t with (* from OF *)
    | None -> 0xffff (* OFPP_NONE *)
    | Some x -> PseudoPort.marshal x

  let del_flow table ?(xid=(Random.int32 Int32.max_int)) 
        ?(reason=Delete) tuple out_port t verbose =

	let port_num = marshal_optional out_port in
    (* Delete all matching entries from the flow table*)
    let remove_flow = 
      Hashtbl.fold (
        fun of_match flow ret -> 
          if ((SMatch.flow_match_compare of_match tuple) && 
              ((port_num = 0xffff) ||  (* XXX we don't have this type in OF_Core *)
               (is_output_port port_num flow.Entry.actions))) then ( 
            let _ = Hashtbl.remove table.entries of_match in 
            
            (* log removal of flow *)
(*            let _ = 
              match Lwt.get OS.Topology.node_name with
              | None -> ()
              | Some(node_name) -> 
                  let flow_str = OP.Match.match_to_string of_match in
                  let action_str = OP.Flow.string_of_actions flow.Entry.actions in
                  let msg = Rpc.Dict [ 
                    ("name", (Rpc.String node_name));
                    ("type", (Rpc.String "del"));
                    ("flow", (Rpc.String flow_str)); 
                    ("action", (Rpc.String action_str));] in
                    OS.Console.broadcast "flow" (Jsonrpc.to_string msg)
    in *)
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
            pp "[switch] Removing flow %s" (Match.to_string of_match)
        in 
        match(t, Entry.notify_when_removed_of_flags flow.Entry.counters.Entry.flags (*.OP.Flow_mod.send_flow_rem *)) with
        | (Some t, true) -> 
          let duration_sec = (int_of_float (Clock.time ()))  -
            flow.Entry.counters.Entry.insert_sec in
          let fl_rm = (
            {pattern = of_match; cookie=flow.Entry.counters.Entry.cookie; 
            priority=flow.Entry.counters.Entry.priority;
            reason; duration_sec=(Int32.of_int duration_sec); duration_nsec=0l;
            idle_timeout=flow.Entry.counters.Entry.idle_timeout;
            packet_count=flow.Entry.counters.Entry.n_packets;
            byte_count=flow.Entry.counters.Entry.n_bytes;}) in
				OSK.send_packet t (Message.marshal xid (FlowRemovedMsg fl_rm)) 
        | _ -> return ()
    ) remove_flow

(*	return *)


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
	let monitor_flow_timeout table t verbose = 
	  let open Entry in
		let check_flow_timeout table t verbose = 
		  let ts = int_of_float (Clock.time ()) in 
		  let flows = Hashtbl.fold (
		    fun of_match entry ret -> 
		      let hard = ts - entry.counters.insert_sec in
		      let idle = ts - entry.counters.last_sec in
		      match (hard, idle) with 
		        | (l, _) when ((Timeout.to_int entry.counters.hard_timeout > 0) && 
		                       (l >= Timeout.to_int entry.counters.hard_timeout)) ->
		            (of_match, entry, HardTimeout )::ret
		        | (_, l) when ((Timeout.to_int entry.counters.idle_timeout > 0) &&
		                       (l >= Timeout.to_int entry.counters.idle_timeout)) ->
		            ret @ [(of_match, entry, IdleTimeout )]
		        | _ -> ret 
		  ) table.entries [] in 
		    Lwt_list.iter_s (
		      fun (of_match, entry, reason) -> 
		        del_flow table ~reason of_match None (* output port *) t verbose (* XXX important: check *)
		    ) flows
		in
		while_lwt true do 
		  lwt _ = OS.Time.sleep 1.0 in 
		    check_flow_timeout table t verbose 
		done 

	end
  (* end of module table *)

  let init_port port_no ethif =
    let name = "" in (* XXX TODO *)
	let hw_addr = Packet.mac_of_string (Macaddr.to_string (E.mac ethif)) in
    let (in_queue, in_push) = Lwt_stream.create () in
    let (out_queue, out_push) = Lwt_stream.create () in
    let counter = 
        { port_id=port_no; rx_packets=0L; tx_packets=0L; rx_bytes=0L; 
          tx_bytes=0L; rx_dropped=0L; tx_dropped=0L; rx_errors=0L; 
          tx_errors=0L; rx_frame_err=0L; rx_over_err=0L; rx_crc_err=0L; 
          collisions=0L;} in
    let features = PortDescription.PortFeatures.(
        {f_10MBHD=true; f_10MBFD=true; f_100MBHD=true; f_100MBFD=true;
		 f_1GBHD=true; f_1GBFD=true; f_10GBFD=true;
		 copper=true; fiber=true; autoneg=true; pause=true; pause_asym=true; }) in
    let config = PortDescription.PortConfig.(
        { down=false; no_stp=false; no_recv=false; 
          no_recv_stp=false; no_flood=false; no_fwd=false; 
          no_packet_in=false;}) in 
    let state = PortDescription.PortState.(
        {down =false; stp_state = Listen}) in
    let phy' = PortDescription.(
        {port_no; hw_addr; name; config;
         state; curr=features; advertised=features; 
         supported=features; peer=features;}) in
    
    {port_id=port_no; port_name=name; counter; 
	 ethif=ethif; phy'; in_queue; in_push; pkt_count=0;
	 out_queue; out_push;}


  type stats = {
    mutable n_frags: int64;
    mutable n_hits: int64;
    mutable n_missed: int64;
    mutable n_lost: int64;
  }

  type lookup_ret = 
         Found of Entry.t ref
       | NOT_FOUND

  type t' = {
    (* Mapping Netif objects to ports *) (* XXX each port has Netif record, do we need it here anymore? *)
    (* mutable dev_to_port: (Net.Manager.id, port ref) Hashtbl.t; *)
    (* Mapping port ids to port numbers *)
    mutable int_to_port: (int, port ref) Hashtbl.t;
    mutable ports : port list;
    mutable controller: OSK.conn_state option;
    mutable last_echo_req : float;
    mutable echo_resp_received : bool;
    table: Table.t;
    stats: stats;
    mutable errornum : int32;
    mutable portnum : int;
    mutable features' : SwitchFeatures.t;
    mutable packet_buffer: PacketIn.t list; (* OP.Packet_in.t list; *)
    mutable packet_buffer_id: int32;
    ready : unit Lwt_condition.t;
    verbose : bool;
    mutable pkt_len : int;
  }

 let supported_actions () =
   SwitchFeatures.SupportedActions.({ output=true; set_vlan_id=true; set_vlan_pcp=true; strip_vlan=true;
   set_dl_src=true; set_dl_dst=true; set_nw_src=true; set_nw_dst=true;
   set_nw_tos=true; set_tp_src=true; set_tp_dst=true; enqueue=false;vendor=true; })

 let supported_capabilities () = 
   SwitchFeatures.Capabilities.({flow_stats=true;table_stats=true;port_stats=true;stp=true;
   ip_reasm=false;queue_stats=false;arp_match_ip=true;})

  let switch_features datapath_id = 
	SwitchFeatures.({
	  switch_id= datapath_id;
	  num_buffers=0l;
	  num_tables=1; 
	  supported_capabilities=(supported_capabilities ());
	  supported_actions=(supported_actions ());
	  ports=[];})

  let update_port_tx_stats pkt_len (port : port)= 
    port.counter.tx_packets <- (Int64.add port.counter.tx_packets 1L);
    port.counter.tx_bytes <- (Int64.add port.counter.tx_bytes pkt_len)

  let update_port_rx_stats pkt_len (port : port) = 
    port.counter.rx_packets <- Int64.add port.counter.rx_packets 1L;
    port.counter.rx_bytes <- Int64.add port.counter.rx_bytes pkt_len

  (* we have exactly the same function in pcb.mli *)
  let tcp_checksum ~src ~dst =
	let open SMatch in
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

  let forward_frame (st : t') (* it has controller *) in_port bits checksum port = 
	let open SMatch in
    let _ = 
      if ((checksum) && ((get_dl_header_dl_type bits) = 0x800)) then 
        let ip_data = Cstruct.shift bits sizeof_dl_header in
        let len = (get_nw_header_hlen_version ip_data) land 0xf in 
        let _ = SMatch.set_nw_header_csum ip_data 0 in
        let csm = Tcpip_checksum.ones_complement (Cstruct.sub ip_data 0 (len*4)) in
        let _ = SMatch.set_nw_header_csum ip_data csm in
        let _ = 
          match (get_nw_header_nw_proto ip_data) with
          | 6 (* TCP *) -> 
              let src = Ipaddr.V4.of_int32 (SMatch.get_nw_header_nw_src
              ip_data) in 
              let dst = Ipaddr.V4.of_int32 (SMatch.get_nw_header_nw_dst
              ip_data) in 
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
        return (pp "[switch] forward_frame: Port %d not registered\n%!" portId)
(*    | OP.Port.No_port -> return () *) (* XXX check *)
    | Flood 
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

    | InPort -> begin
	  match in_port with
	  | Some port ->
		  if Hashtbl.mem st.int_to_port port then
		    send_frame (!(Hashtbl.find st.int_to_port port))  bits
		  else
		    return (pp "[switch] forward_frame: Port %d unregistered\n%!" port)
	  | None ->
			return (pp "[switch] forward_frame: Input port undefined!") (* XXX return error to the controller? *)
	  end
    | Local ->
      let local = (PseudoPort.marshal Local) in 
      if Hashtbl.mem st.int_to_port local then
        send_frame !(Hashtbl.find st.int_to_port local) bits
      else 
        return (pp "[switch] forward_frame: Port %d unregistered \n%!" local)
	(* XXX Controller port is removed ... *)
    | Controller c -> begin (* XXX c doesn't exists in manual?! *)
       match st.controller with
       | None -> return ()
       | Some conn -> 
		  match in_port with
		  | Some port ->
			  let pkt_in = ({ input_payload = NotBuffered bits
							; total_len = Cstruct.len bits
							; port
							; reason = ExplicitSend
							}) in
				OSK.send_packet conn (Message.marshal (Random.int32 Int32.max_int) (PacketInMsg pkt_in)) 
		  | None ->
			  return (pp "[switch] forward_frame: Input port undefined!") (* XXX return error to the controller? *)
       end 
        (*           | Table
         *           | Normal  *)
	| _ -> 
	  return (pp "[switch] forward_frame: unsupported output port\n")


  (* Assume that action are valid. I will not get a flow that sets an ip
   * address unless it defines that the ethType is ip. Need to enforce
   * these rule in the parsing process of the flow_mod packets *)
  let apply_of_actions (st : t') in_port bits (actions : action list) =
	let open SMatch in
    let apply_of_actions_inner (st : t') in_port bits checksum action =
      try_lwt
        match action with
        | Output port ->
          (* Make a packet copy in case the buffer is modified and multiple
           * outputs are defined? *)
          lwt _ = forward_frame st in_port bits checksum port in 
          return false 
        | SetDlSrc eaddr ->
          let _ = set_dl_header_dl_src (Int64.to_string eaddr) 0 bits in 
          return checksum 
        | SetDlDst eaddr ->
          let _ = set_dl_header_dl_dst (Int64.to_string eaddr) 0 bits in 
          return checksum 
  (* TODO: Add for this actions to check when inserted if 
    * the flow is an ip flow *)
        | SetNwTos tos -> 
          let ip_data = Cstruct.shift bits sizeof_dl_header in
          let _ = set_nw_header_nw_tos ip_data tos in
          return true 
  (* TODO: wHAT ABOUT ARP?
   * *)
        | SetNwSrc ip -> 
          let ip_data = Cstruct.shift bits sizeof_dl_header in
          let _ = set_nw_header_nw_src ip_data ip in 
          return true 
        | SetNwDst ip -> 
          let ip_data = Cstruct.shift bits sizeof_dl_header in
          let _ = set_nw_header_nw_dst ip_data ip in 
          return true 
        | SetTpSrc port ->
          let ip_data = Cstruct.shift bits sizeof_dl_header in
          let len = (get_nw_header_hlen_version ip_data) land 0xf in 
          let tp_data = Cstruct.shift ip_data (len*4) in
          let _ = set_tp_header_tp_src tp_data port in 
          return true 
        | SetTpDst port ->
          let ip_data = Cstruct.shift bits sizeof_dl_header in
          let len = (get_nw_header_hlen_version ip_data) land 0xf in 
          let tp_data = Cstruct.shift ip_data (len*4) in 
          let _ = set_tp_header_tp_dst tp_data port in 
          return true 
  (*      | OP.Flow.Enqueue(_, _)
          | OP.Flow.Set_vlan_pcp _
          | OP.Flow.Set_vlan_vid _
          | OP.Flow.VENDOR_ACT 
          | OP.Flow.STRIP_VLAN *)
        | act ->
          let _ = (pp "[switch] apply_of_actions: Unsupported action %s" 
                        (Action.to_string act)) in (* XXX what happens if action doesn't exist at all? *)
          return checksum
      with exn -> 
        let _ = (pp  "[switch] apply_of_actions: (packet size %d) %s %s\n%!" 
                     (Cstruct.len bits) (Action.to_string action) 
                     (Printexc.to_string exn )) in
        return checksum 
    in
    let rec apply_of_actions_rec (st : t') in_port bits checksum = function
      | [] -> return false
      | head :: actions -> 
        lwt checksum = apply_of_actions_inner st in_port bits checksum head in
        apply_of_actions_rec st in_port bits checksum actions 
    in 
    lwt _ = apply_of_actions_rec st in_port bits false actions in 
    return ()


  let lookup_flow (st : t') of_match =
  (* Check first the match table cache
   * NOTE an exact match flow will be found on this step and thus 
   * return a result immediately, without needing to get to the cache table
   * and consider flow priorities *)
	let _ = pp "[switch] comparing flow %s\n" (Match.to_string of_match) in
	if (Hashtbl.mem st.table.cache of_match) then
       let entry = (Hashtbl.find st.table.cache of_match) in
     	Found(entry) 
	else begin
     (* Check the wilcard card table *)
	  let lookup_flow flow entry r =
		match (r, SMatch.flow_match_compare of_match flow) with
		| (_, false) -> r
		| (None, true) -> Some(flow, entry)
		| (Some(f,e), true) when (Entry.(e.counters.priority > entry.counters.priority)) -> r
		| (Some(f,e), true) when (Entry.(e.counters.priority <= entry.counters.priority)) -> 
		   Some(flow, entry)
		| (_, _) -> r
		in
		let flow_match = Hashtbl.fold lookup_flow st.table.entries None in
		  match (flow_match) with
		  | None ->  NOT_FOUND
		  | Some(f,e) ->
		    Hashtbl.add st.table.cache of_match (ref e);
		    Entry.(e.cache_entries <- of_match :: e.cache_entries); 
		  	  Found (ref e)
	end

  let create_tcp_connection tcp (contaddr, contport) =
	T.create_connection tcp (Ipaddr.V4.of_string_exn contaddr, contport)
	>>= function 
		  | `Error e -> fail (Failure "[Swicth] failed connecting to the controller")
		  | `Ok fl -> (return fl)  (* returns flow *)

  let process_frame st (p : port) frame =
	let _ = p.pkt_count <- p.pkt_count + 1 in
      p.in_push (Some frame);
	  return ()

  let init_switch_info ?(verbose=true) dpid = 
	{ (* dev_to_port=(Hashtbl.create 64); *)
	int_to_port = (Hashtbl.create 64); ports = [];
	controller=None;
	last_echo_req=0.; echo_resp_received=true;
	stats= {n_frags=0L; n_hits=0L; n_missed=0L; n_lost=0L;};
	errornum = 0l; portnum=0;
	table = (Table.init_table ());
	features'=(switch_features dpid); 
	packet_buffer=[]; packet_buffer_id=0l; ready=(Lwt_condition.create ());
	verbose; pkt_len=1500;}

(* add port to the switch *) 
  let add_port ?(use_mac=false) (sw : t') ethif = 

	sw.portnum <- sw.portnum + 1;
	let hw_addr =  Macaddr.to_string (E.mac ethif) in
	(* let dev_name = N.id (E.id ethif) in *) (* TODO : how to extract dev_name? *)
	let _ = pp "[switch] Adding port %d '%s' \n%!" 
								sw.portnum hw_addr in
	let port = init_port sw.portnum ethif in 
	  sw.ports <- sw.ports @ [port]; 
	  Hashtbl.add sw.int_to_port sw.portnum (ref port); 
	  sw.features' <- {
		switch_id = sw.features'.switch_id;
		num_buffers = sw.features'.num_buffers;
		num_tables = sw.features'.num_tables; 
		supported_capabilities = sw.features'.supported_capabilities;
		supported_actions = sw.features'.supported_actions;
		ports = sw.features'.ports @ [port.phy'];};
	  let _ = N.listen (E.id ethif) (process_frame sw port) in 
	  match sw.controller with
		| None -> return ()
		| Some t -> OSK.send_packet t 
			(Message.marshal (Random.int32 Int32.max_int) (PortStatusMsg {reason = Add; desc = port.phy'}))
  

  let get_flow_stats (st : t') (ptrn : Match.t) =
	let match_flows ptrn key value ret =
	  if (SMatch.flow_match_compare key ptrn (* wcard *)) then ( 
	  (Entry.flow_counters_to_flow_stats key (1) value)::ret  (* XXX table id? *)
	  ) else 
        ret 
	in
	  Hashtbl.fold (fun key value r -> match_flows ptrn key value r) 
	  st.table.Table.entries []  

let process_buffer_id (st : t') t msg xid buffer_id actions = (* XXX important: check functionality *)
  let pkt_in = ref None in

  let _ = 
	st.packet_buffer <- (* Do we need to keep this big list? Also, pkt_in is the last one in the buffer?! *)
      List.filter ( fun a -> 
		match a.input_payload with
		| NotBuffered p -> true (* XXX what we can do? *)
		| Buffered (n, p) -> 
			if (n = buffer_id) then
    	  		(pkt_in := Some (a); false )
			else true 
			) st.packet_buffer in 
			  match (!pkt_in) with 
				| None ->
					pp "[switch**] invalid buffer id %ld\n%!" buffer_id; 
					OSK.send_packet t (Message.marshal xid (ErrorMsg (Error (Error.BadRequest BufferUnknown, msg))))
					(* XXX in testing with Beacon, if Beacon runs on the same machine,
						it sends OF Packet_Out twice in one TCP packet (as PDU.)
						Beacon works fine when it runs on a different machine. (Check the reason.)
					*) 
				| Some (pkt_in) ->
					apply_of_actions st (Some pkt_in.port) msg actions (* XXX is it correct? pkt_in.data or msg? *)
	

let process_openflow (st : t') t (xid, msg) =
  let open Message in

  let _ = if st.verbose then pp "[switch*] %s\n%!" (Message.to_string msg) in

  match msg with
	| Hello buf -> return ()
	| EchoRequest buf -> (* Reply to ECHO requests *)
    	OSK.send_packet t (Message.marshal xid msg) 
	| EchoReply buf -> return (st.echo_resp_received <- true) 
	| SwitchFeaturesRequest  -> 
    	OSK.send_packet t (Message.marshal xid (SwitchFeaturesReply st.features')) 
	| StatsRequestMsg req -> begin
		match req with
		  | DescriptionRequest ->
			let p = DescriptionRep 
						{ manufacturer = "Mirage"
						; hardware = "Mirage"
						; software = "Mirage"
						; serial_number = "0.1"
						; datapath = "Mirage" } in 
 			  OSK.send_packet t (Message.marshal xid (StatsReplyMsg p)) 
	(*	  | FlowTableStatsRequest ->  (* XXX important: no specific reply is defined in frenetic *)
			  let p = IndividualFlowRep [st.table.Table.stats] in 
				OSK.send_packet t (Message.marshal xid (StatsReplyMsg p)) *)
				 
		  | IndividualRequest sreq -> (* (req_h, of_match, table_id, out_port) *)
			  (*TODO Need to consider the  table_id and the out_port and 
			   * split reply over multiple openflow packets if they don't
			   * fit a single packet. *)
			  let flows = get_flow_stats st sreq.is_of_match in (* XXX check the change *)
			(* (* XXX size restriction removed. check *)
			  let stats = OP.Stats.({st_ty=FLOW; more=true;}) in 
			  lwt (_, flows) = 
				Lwt_list.fold_right_s (
				  fun fl (sz, flows) ->
				    let fl_sz = OP.Flow.flow_stats_len fl in 
				      if (sz + fl_sz > 0xffff) then 
				        let r = OP.Stats.Flow_resp(stats, flows) in
				        let h = OP.Header.create ~xid STATS_RESP (OP.Stats.resp_get_len r) in 
				        lwt _ = OSK.send_packet t (OP.Stats_resp (h, r)) in
					        return ((OP.Header.get_len + OP.Stats.get_resp_hdr_size + fl_sz), [fl])
				      else
				        return ((sz + fl_sz), (fl::flows)) )
				  flows ((OP.Header.get_len + OP.Stats.get_resp_hdr_size), []) in *)
(* 
			  let stats = OP.Stats.({st_ty=FLOW; more=false;}) in 
			  let r = OP.Stats.Flow_resp(stats, flows) in
			  let h = OP.Header.create ~xid STATS_RESP (OP.Stats.resp_get_len r) in
			  OSK.send_packet t (OP.Stats_resp (h, r)) *)
			  OSK.send_packet t (Message.marshal xid (StatsReplyMsg (IndividualFlowRep flows)))
			  
		  | AggregateRequest areq -> 
			  let match_flows_aggr of_match key value (fl_b, fl_p, fl) =
				let open Entry in
				if (SMatch.flow_match_compare key of_match) then (* XXX get_flow_stats? *)
				  ((Int64.add fl_b value.counters.n_bytes), (Int64.add fl_p
				  value.counters.n_packets), (Int32.succ fl))
				else (fl_b, fl_p, fl) in 
			  let (byte_count, packet_count,flow_count) = 
				Hashtbl.fold (match_flows_aggr areq.as_of_match) 
					st.table.Table.entries (0L, 0L, 0l) in
					OSK.send_packet t (Message.marshal xid (StatsReplyMsg (AggregateFlowRep 
					  {total_byte_count = byte_count; total_packet_count = packet_count;flow_count;})))
(*
		  | OP.Stats.Port_req(req_h, port) -> begin
			   match port with
			   | OP.Port.No_port -> 
				 let port_stats = List.map (fun p -> p.counter) st.ports in
				 let stats = OP.Stats.({st_ty=PORT; more=false;}) in 
				 let r = OP.Stats.Port_resp(stats, port_stats) in 
				 let h = OP.Header.create ~xid OP.Header.STATS_RESP (OP.Stats.resp_get_len r) in 
				 OSK.send_packet t (OP.Stats_resp (h, r)) 
			   | OP.Port.Port(port_id) -> begin
				   try_lwt 
				    let port = Hashtbl.find st.int_to_port port_id in
				    let stats = OP.Stats.({st_ty=PORT; more=false;}) in 
				    let r = OP.Stats.Port_resp(stats, [(!port).counter]) in 
				    let h = create ~xid STATS_RESP (OP.Stats.resp_get_len r) in 
				    OSK.send_packet t (OP.Stats_resp (h, r))
				   with Not_found ->
				  (* TODO reply with right error code *)
				      pp "[switch] unregistered port %s\n%!"(OP.Port.string_of_port port);
				      let h = create ~xid ERROR (OP.Header.get_len + 4) in 
				      OSK.send_packet t (OP.Error (h, OP.ACTION_BAD_OUT_PORT, (get_new_buffer 0)))
				  end 
			  | _ -> 
          		pp "[switch] unsupported stats request\n%!";
				let h = create ~xid ERROR (get_len + 4) in 
				OSK.send_packet t OP.(Error (h, ACTION_BAD_OUT_PORT, (marshal msg))) 
		  end *)
		  | _ ->
			OSK.send_packet t (Message.marshal xid (ErrorMsg (Error (Error.BadRequest BadSubType, Cstruct.create 0))))
	end 

  | ConfigRequestMsg ->
		OSK.send_packet t (Message.marshal xid (ConfigReplyMsg { frag_flags = FragNormal; miss_send_len = st.pkt_len}))
			(* XXX check it *)

  | BarrierRequest ->
	  OSK.send_packet t (Message.marshal xid (BarrierReply))

  | PacketOutMsg pkt ->
	begin
	  match pkt.output_payload with 
		| NotBuffered p -> apply_of_actions st pkt.port_id p pkt.apply_actions (* pkt.port_id : portId option *)
		| Buffered (n, p) -> process_buffer_id st t p xid n pkt.apply_actions 
	end

  | FlowModMsg fm ->
      lwt _ = 
        match fm.command with
          | AddFlow | ModFlow | ModStrictFlow -> 
            Table.add_flow st st.table fm st.verbose
          | DeleteFlow | DeleteStrictFlow ->
            (* Need to implemente strict deletion in order to enable signpost
             * switching *)
            Table.del_flow st.table fm.pattern fm.out_port (Some t) st.verbose 
	  in
		return ()

  | SetConfig msg -> 
          (* use miss_send_len when sending a pkt_in message*)
          let _ = st.pkt_len <- msg.miss_send_len in
          return ()
(*
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
	  OSK.send_packet t (Message.marshal xid (ErrorMsg (Error (Error.BadRequest BadType, Cstruct.create 0))))

(* end of process_openflow *)

(*************************************************
 * Switch OpenFlow control channel 
 *************************************************)

  let monitor_control_channel (sw : t') conn =
	let is_active = ref true in 
  	while_lwt !is_active do
      let _ = sw.echo_resp_received <- false in 
      let _ = sw.last_echo_req <- (Clock.time ()) in 
      lwt _ = OSK.send_packet conn (Message.marshal 1l (EchoRequest (Cstruct.create 0))) in
		lwt _ = OS.Time.sleep 10.0 in 
		return (is_active := sw.echo_resp_received) 
	done 

  let control_channel_run (st : t') conn = 
	(* Trigger the dance between the 2 nodes *)
	(*let h = OP.Header.(create ~xid:1l HELLO sizeof_ofp_header) in  
	let _ = OSK.send_packet conn (OP.Hello(h)) in *)
	let _ = OSK.send_packet conn (Message.marshal 1l (Hello (Cstruct.create 0))) in

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
		return (pp "[switch] control channel thread returned")


  (*********************************************
   * Switch OpenFlow data plane 
   *********************************************)

(* in checking progress ... *)
  let process_frame_inner (st : t') (p : port) frame =
  	try_lwt
      let in_port = p.port_id in 
      let tupple = (SMatch.raw_packet_to_match in_port frame)  in 
	  (* Update port rx statistics *)
	  let _ = update_port_rx_stats (Int64.of_int (Cstruct.len frame)) p in

	  (* Lookup packet flow to existing flows in table *)
		match  (lookup_flow st tupple) with 
		  | NOT_FOUND -> begin
			  (* Table.update_table_missed st.table; *) (* XXX check, do we need it? *)
			  let buffer_id = st.packet_buffer_id in
			  (*TODO Move this code in the Switch module *)
			  st.packet_buffer_id <- Int32.add st.packet_buffer_id 1l; (*XXX check what is this *)
			  let pkt_in = ({ input_payload = Buffered (buffer_id, frame)
							; total_len = Cstruct.len frame
							; port = in_port
							; reason = NoMatch
							}) in
			  st.packet_buffer <- pkt_in::st.packet_buffer; 

			  (* Disable for now packet trimming for buffered packets *)
			  let size =
				if (Cstruct.len frame > 92) then 92
				else Cstruct.len frame in
				  let pkt_in = ({ input_payload = Buffered (buffer_id, Cstruct.sub frame 0 size)
							; total_len = Cstruct.len frame
							; port = in_port
							; reason = NoMatch
							}) in				  
					return (
					  match st.controller with
						| None -> pp "[switch] Controller not set."
						| Some conn ->
							  ignore_result 
								(OSK.send_packet conn (Message.marshal (Random.int32 Int32.max_int) (PacketInMsg pkt_in)))
					)
      		end (* switch not found*)
	       (* generate a packet in event *)
		| Found (entry) ->
			let _ = print_endline "entry found..." in
			(* let _ = Table.update_table_found st.table in *)
			let _ = Entry.update_flow (Int64.of_int (Cstruct.len frame)) !entry in
			apply_of_actions st tupple.inPort frame (!entry).Entry.actions
	  
	  with exn ->
		return (pp "[switch] process_frame_inner: control channel error: %s\n" 
        	(Printexc.to_string exn))


  (* Swicth operation *)
  let forward_thread (st : t') =
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
		  let sw = init_switch_info 0x100L (* model *) in (* XXX move "verbose" and "dpid" to the unikernel *)
		  lwt _ = add_switch_ports sw ethlist in
		  connect_socket ()
			>>= fun fl -> 
				let conn = OSK.init_socket_conn_state (OSK.create fl)
				  in (* up to here, connection in stablished correctly *) 
					let _ = sw.controller <- (Some conn) in 
					lwt _ = ((control_channel_run sw conn) <&> (forward_thread sw) ) in 
		  			let _ = OSK.close conn in 
      				  return (pp "[switch] Disconnected from remote controller.\n")


end (* end of Switch module *)

