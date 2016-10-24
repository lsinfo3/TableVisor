%% Copyright (c) 2013-2015, Michael Santos <michael.santos@gmail.com>
%% All rights reserved.
%%
%% Redistribution and use in source and binary forms, with or without
%% modification, are permitted provided that the following conditions
%% are met:
%%
%% Redistributions of source code must retain the above copyright
%% notice, this list of conditions and the following disclaimer.
%%
%% Redistributions in binary form must reproduce the above copyright
%% notice, this list of conditions and the following disclaimer in the
%% documentation and/or other materials provided with the distribution.
%%
%% Neither the name of the author nor the names of its contributors
%% may be used to endorse or promote products derived from this software
%% without specific prior written permission.
%%
%% THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
%% "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
%% LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
%% FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
%% COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
%% INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
%% BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
%% LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
%% CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
%% LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
%% ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
%% POSSIBILITY OF SUCH DAMAGE.
-module(pkt_ipv6_ah).

%% RFC 4302: IP Authentication Header

-include("pkt_ipproto.hrl").
-include("pkt_ipv6.hrl").

-export([codec/1]).

codec(
    <<Next:8, Len:8, Res:16, SPI:32, Seq:32, Rest/binary>>
) ->
    % the length of AH in 32-bit words (4-byte units), minus "2"
    %  Next + Len + Res = 32 bits
    %  SPI = 32 bits
    % The length is the 32-bit sequence number + the ICV
    %
    % XXX for IPv6, must be a multiple of 8-octets
    ICVLen = ((Len - 1) * 4),
    <<ICV:ICVLen/bytes, Payload/binary>> = Rest,
    {#ipv6_ah{
        next = Next,
        len = Len,
        res = Res,
        spi = SPI,
        seq = Seq,
        icv = ICV
    }, Payload};
codec(#ipv6_ah{
        next = Next,
        len = Len,
        res = Res,
        spi = SPI,
        seq = Seq,
        icv = ICV
        }) ->
    <<Next:8, Len:8, Res:16, SPI:32, Seq:32, ICV/binary>>.
