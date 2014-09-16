(*
 * Copyright (c) 2014 Masoud Koleini <masoud.koleini@nottingham.ac.uk>
 * Copyright (c) 2011 Haris Rotsos <cr409@cl.cam.ac.uk>
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

open Lwt
open OpenFlow0x01

module Header = OpenFlow_Header
module Message = OpenFlow0x01.Message

let resolve t = Lwt.on_success t (fun _ -> ())

let get_new_buffer len = 
  let buf = Io_page.to_cstruct (Io_page.get 1) in 
    Cstruct.sub buf 0 len 

module Make(T:V1_LWT.TCPV4) = struct  

  module Channel = Channel.Make(T)

  type ch = Channel.t
  type fl = Channel.flow
  type t = {
	sock: Channel.t;
	data_cache: Cstruct.t ref; 
  }

  type conn_state = {
	mutable dpid : switchId;
	t : t; 
  }

  let create_socket sock = 
	{ sock; data_cache=ref (get_new_buffer 0);}

  let init_socket_conn_state t = 
	{dpid=0L; t=create_socket t;}

  let read_packet conn =
	lwt hbuf = Channel.read_some conn.t.sock ~len:(Header.size) in  
	let ofh  = Header.parse hbuf in
	let dlen = ofh.length - Header.size in 
	lwt dbuf = 
	  if (dlen = 0) then 
	    return (Cstruct.create 0)
	  else
	    Channel.read_some conn.t.sock ~len:dlen 
	  in 
		let ofp  = Message.parse ofh (Cstruct.to_string dbuf) in
		  return ofp

  let write_buffer t bits =
	  let _ = Channel.write_buffer t.sock bits in  
		Channel.flush t.sock

  (* send packet *)
  let send_packet conn ofp = 
	write_buffer conn.t (Cstruct.of_string ofp)

  (* send raw data *)
  let send_data_raw conn bits = 
	let _ = Channel.write_buffer conn.sock bits in 
	  Channel.flush conn.sock

  (* close channel *)
  let close conn = 
	resolve (
	  try_lwt
		Channel.close conn.t.sock
	  with exn -> 
        return (Printf.printf "[socket] close error: %s\n%!" (Printexc.to_string exn))
    ) 

  let create flow = Channel.create flow

end
