(*
 * Copyright (c) 2014 Masoud Koleini <masoud.koleini@nottingham.ac.uk>
 * Copyright (c) 2012 Haris Rotsos <cr409@cl.cam.ac.uk>
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

module Make(T:TCPV4) : sig
  type ch (* channel *)
  type fl = Channel.Make(T).flow (* XXX can I do it better? I cannot define it abstrct *)
  type conn_state

  val read_packet : conn_state -> (OpenFlow_Header.xid * OpenFlow0x01.Message.t) Lwt.t

  val send_packet : conn_state -> string -> unit Lwt.t
  val close : conn_state -> unit
  val create : fl -> ch
  val init_socket_conn_state : ch -> conn_state

end

