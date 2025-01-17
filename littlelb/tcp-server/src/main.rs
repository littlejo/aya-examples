use std::io;
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::main]
async fn main() {
    let servers = vec![
        tokio::spawn(run_server(8081)),
        tokio::spawn(run_server(8082)),
        tokio::spawn(run_server(8083)),
    ];

    for server in servers {
        server.await.expect("server failed").unwrap();
    }
}

async fn run_server(port: u16) -> io::Result<()> {
    let bind_addr = format!("127.0.0.1:{}", port);
    let listener = TcpListener::bind(&bind_addr).await?;
    println!("Listening on {}", bind_addr);

    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                println!("New connection from {}", addr);
                tokio::spawn(handle_connection(port, stream));
            }
            Err(e) => {
                eprintln!("Failed to accept connection: {}", e);
            }
        }
    }
}

async fn handle_connection(port: u16, mut stream: TcpStream) -> io::Result<()> {
    let mut buf = [0; 4];

    loop {
        match stream.read(&mut buf).await {
            Ok(0) => {
                println!("port {}: Connection closed by client", port);
                return Ok(());
            }
            Ok(len) => {
                println!(
                    "port {}: {} bytes received: {}",
                    port,
                    len,
                    String::from_utf8_lossy(&buf[..len])
                );
                // Echo the data back to the client
                stream.write_all(&buf[..len]).await?;
            }
            Err(e) => {
                eprintln!("port {}: Failed to read from socket: {}", port, e);
                return Err(e);
            }
        }
    }
}
