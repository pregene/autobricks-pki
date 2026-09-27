use crate::{
    Result,
    server::{routes, service::Service},
    transport::{
        management::{self, Message, Reply},
        request::{MAX_BODY, Request},
        response::write_response,
        tls,
    },
};
use std::{
    net::{TcpListener, TcpStream},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

#[derive(Clone, Copy)]
enum Kind {
    Management,
    Https,
}
struct Active(Arc<AtomicUsize>);
impl Drop for Active {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Release);
    }
}

pub fn serve(
    management_listener: TcpListener,
    https_listener: TcpListener,
    service: Arc<Mutex<Service>>,
) -> Result<()> {
    management_listener.set_nonblocking(true)?;
    https_listener.set_nonblocking(true)?;
    let active = Arc::new(AtomicUsize::new(0));
    loop {
        let mut accepted = false;
        for (listener, kind) in [
            (&management_listener, Kind::Management),
            (&https_listener, Kind::Https),
        ] {
            let socket = match listener.accept() {
                Ok((socket, _)) => socket,
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                    ) =>
                {
                    continue;
                }
                Err(e) => return Err(e.into()),
            };
            accepted = true;
            if active
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                    (n < 32).then_some(n + 1)
                })
                .is_err()
            {
                continue;
            }
            let guard = Active(active.clone());
            let service = service.clone();
            std::thread::Builder::new()
                .name("abpkid-connection".into())
                .spawn(move || {
                    let _guard = guard;
                    if handle(socket, kind, service).is_err() {
                        eprintln!("TLS connection failed");
                    }
                })?;
        }
        if !accepted {
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

fn handle(socket: TcpStream, kind: Kind, service: Arc<Mutex<Service>>) -> Result<()> {
    socket.set_nonblocking(false)?;
    let config = service
        .lock()
        .map_err(|_| "service lock failed")?
        .tls_config()?;
    let mut stream = tls::DeadlineStream::new(socket, config)?;
    match kind {
        Kind::Management => {
            let message: Message = management::read_frame(&mut stream, MAX_BODY)?;
            let request = message.into_request()?;
            let response = routes::dispatch(
                &*service.lock().map_err(|_| "service lock failed")?,
                request,
            );
            management::write_frame(
                &mut stream,
                &Reply::from(response),
                management::MAX_RESPONSE,
            )?;
        }
        Kind::Https => match Request::read(&mut stream) {
            Ok(request) => {
                let response = routes::dispatch_public(
                    &*service.lock().map_err(|_| "service lock failed")?,
                    request,
                );
                write_response(
                    &mut stream,
                    response.status,
                    response.content_type,
                    &response.body,
                )?;
            }
            Err(_) => write_response(
                &mut stream,
                "400 Bad Request",
                "text/plain",
                b"Invalid request\n",
            )?,
        },
    }
    stream.tls.conn.send_close_notify();
    std::io::Write::flush(&mut stream)?;
    Ok(())
}
