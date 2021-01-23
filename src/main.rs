extern crate futures;
extern crate libc;
extern crate thrussh;
extern crate thrussh_keys;
extern crate tokio;

use std::sync::Arc;

use thrussh::*;
use thrussh::server::{Auth, Session};
use thrussh_keys::*;

#[tokio::main]
async fn main() {
    let mut config = thrussh::server::Config::default();
    config.connection_timeout = Some(std::time::Duration::from_secs(10));
    config.auth_rejection_time = std::time::Duration::from_secs(1);
    let server_key = thrussh_keys::key::KeyPair::generate_ed25519().unwrap();
    config.keys.push(server_key);
    let config = Arc::new(config);
    let sh = Server {};
    thrussh::server::run(config, "0.0.0.0:2222", sh).await;
}

#[derive(Clone)]
struct Server {}

impl server::Server for Server {
    type Handler = Self;

    fn new(&mut self, _: Option<std::net::SocketAddr>) -> Self {
        self.clone()
    }
}

impl server::Handler for Server {
    type Error = anyhow::Error;
    type FutureAuth = futures::future::Ready<Result<(Self, server::Auth), anyhow::Error>>;
    type FutureUnit = futures::future::Ready<Result<(Self, Session), anyhow::Error>>;
    type FutureBool = futures::future::Ready<Result<(Self, Session, bool), anyhow::Error>>;

    fn finished_auth(self, auth: Auth) -> Self::FutureAuth {
        println!("finished_auth");
        futures::future::ready(Ok((self, auth)))
    }

    fn finished_bool(self, b: bool, s: Session) -> Self::FutureBool {
        println!("finished_bool");
        futures::future::ready(Ok((self, s, b)))
    }

    fn finished(self, s: Session) -> Self::FutureUnit {
        println!("finished");
        futures::future::ready(Ok((self, s)))
    }

    fn auth_publickey(self, _: &str, _: &key::PublicKey) -> Self::FutureAuth {
        println!("auth_publickey");
        self.finished_auth(server::Auth::Accept)
    }

    fn channel_open_session(self, channel: ChannelId, session: Session) -> Self::FutureUnit {
        println!("channel_open_session: {:?}", channel);
        self.finished(session)
    }

    fn data(self, channel: ChannelId, data: &[u8], session: Session) -> Self::FutureUnit {
        println!("Channel {:?}: {:?}", channel, data);
        self.finished(session)
    }

    fn pty_request(self, channel: ChannelId, term: &str, col_width: u32, row_height: u32, pix_width: u32, pix_height: u32, modes: &[(Pty, u32)], session: Session) -> Self::FutureUnit {
        println!("pty_request {}, {:?}", term, modes);
        let (master, slave, name) = openpty::openpty(
            None,
            Some(&libc::winsize { ws_row: row_height as u16, ws_col: col_width as u16, ws_xpixel: pix_width as u16, ws_ypixel: pix_height as u16 }),
            None,
        ).expect("Creating pty failed");
        println!("master: {:?} slave: {:?} name: {}", master, slave, name);
        self.finished(session)
    }

    fn shell_request(self, channel: ChannelId, session: Session) -> Self::FutureUnit {
        println!("shell_request");
        self.finished(session)
    }
}