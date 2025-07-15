pub mod outbound;

use async_ringbuf::traits::AsyncProducer;
use private_tun::snell_impl_ver::{client_zfc::ConnType, udp_intf::AsyncRingBufSender};
use tokio_util::sync::CancellationToken;


pub struct Client {
    pub client_tx: tokio::sync::Mutex<AsyncRingBufSender<ConnType>>,
    pub cancel_token: CancellationToken,
}

impl Client {
    pub fn new(
        client_tx: tokio::sync::Mutex<AsyncRingBufSender<ConnType>>,
        cancel_token: CancellationToken,
    ) -> Self {
        Self {
            client_tx,
            cancel_token,
        }
    }
    pub async fn push_event(&self, event: ConnType) -> Result<(), ConnType> {
        self.client_tx.lock().await.push(event).await?;
        Ok(())
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        self.cancel_token.cancel();
    }
}
