use std::{
    io,
    ops::Deref,
    pin::Pin,
    task::{Context, Poll},
};

use futures::{Sink, Stream, ready};

use private_tun::snell_impl_ver::udp_intf::{
    BytesOrPoolItem, UdpRingBufL2TSender, UdpRingBufT2LReceiver,
};
use tracing::instrument;

use crate::{proxy::datagram::UdpPacket, session::SocksAddr};

/// OutboundDatagram wrapper for shadowsocks socket, that takes ShadowsocksUdpIo
/// as underlying I/O
pub struct OutboundDatagramPrivateTun {
    data_send_to_remote: UdpRingBufL2TSender, // local -> target
    data_recved_from_remote: UdpRingBufT2LReceiver, // some address -> local
}

impl OutboundDatagramPrivateTun {
    pub fn new(
        data_send_to_remote: UdpRingBufL2TSender,
        data_recved_from_remote: UdpRingBufT2LReceiver,
    ) -> Self {
        Self {
            data_send_to_remote,
            data_recved_from_remote,
        }
    }
}

impl Sink<UdpPacket> for OutboundDatagramPrivateTun {
    type Error = io::Error;

    fn poll_ready(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        let Self {
            ref mut data_send_to_remote,
            ..
        } = *self;
        ready!(Pin::new(data_send_to_remote).poll_ready(cx)).map_err(|_| {
            io::Error::new(io::ErrorKind::Other, "poll ready failed")
        })?;
        Poll::Ready(Ok(()))
    }

    fn start_send(
        mut self: Pin<&mut Self>,
        item: UdpPacket,
    ) -> Result<(), Self::Error> {
        let Self {
            ref mut data_send_to_remote,
            ..
        } = *self;
        let target = match &item.dst_addr {
            SocksAddr::Ip(addr) => private_tun::address::Address::Socket(*addr),
            SocksAddr::Domain(domain, port) => {
                private_tun::address::Address::Domain(
                    domain.to_string().into_boxed_str(),
                    *port,
                )
            }
        };
        let data = BytesOrPoolItem::Bytes(item.data.into());
        let pkt = (data, target);
        Pin::new(data_send_to_remote).start_send(pkt).map_err(|_| {
            io::Error::new(io::ErrorKind::Other, "start send failed")
        })?;
        Ok(())
    }

    #[instrument(skip(self, cx))]
    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        let Self {
            ref mut data_send_to_remote,
            ..
        } = *self;
        Pin::new(data_send_to_remote)
            .poll_flush(cx)
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "poll flush failed"))
    }

    fn poll_close(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        let Self {
            ref mut data_send_to_remote,
            ..
        } = *self;
        Pin::new(data_send_to_remote)
            .poll_close(cx)
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "poll close failed"))
    }
}

impl Stream for OutboundDatagramPrivateTun {
    type Item = UdpPacket;

    #[instrument(skip(self, cx))]
    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        let Self {
            ref mut data_recved_from_remote,
            ..
        } = *self;
        let data = ready!(Pin::new(data_recved_from_remote).poll_next(cx));
        match data {
            Some(data) => {
                let (data, from_addr) = data;
                let data = data.deref().to_vec();
                Poll::Ready(Some(UdpPacket {
                    data,
                    src_addr: from_addr.into(),
                    dst_addr: SocksAddr::any_ipv4(),
                }))
            }
            None => Poll::Ready(None),
        }
    }
}
