use crate::{
    config::internal::proxy::OutboundPrivateTun,
    proxy::{
        HandlerCommonOptions,
        private_tun::outbound::{Handler, HandlerOptions},
    },
};

impl TryFrom<OutboundPrivateTun> for Handler {
    type Error = crate::Error;

    fn try_from(value: OutboundPrivateTun) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&OutboundPrivateTun> for Handler {
    type Error = crate::Error;

    fn try_from(s: &OutboundPrivateTun) -> Result<Self, Self::Error> {
        let h = Handler::new(HandlerOptions {
            name: s.common_opts.name.to_owned(),
            common_opts: HandlerCommonOptions {
                connector: s.common_opts.connect_via.clone(),
                ..Default::default()
            },
            server: s.common_opts.server.to_owned(),
            port: s.common_opts.port,
            udp: s.udp,
            origin_client_config: s.origin_client_config.clone(),
            is_uot: s.uot,
        });
        Ok(h)
    }
}
