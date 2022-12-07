use std::time::Duration;

use bytes::{ BytesMut, BufMut, Buf };
use tokio::{io::{AsyncWriteExt, AsyncReadExt}, net::TcpStream, time::timeout};
use tracing::info;

use serde::{Serialize, Deserialize};
use unsigned_varint::decode::is_last;

#[derive(Serialize, Deserialize)]
struct IPPortEntry {
    port: u16,
    proto: String,
    status: String,
    reason: String,
    ttl: i16
}

#[derive(Serialize, Deserialize)]
struct IPEntry {
    ip: String,
    timestamp: String,
    ports: Vec<IPPortEntry>
}

#[derive(Serialize, Deserialize)]
struct MOTDDescription {
    text: String
}

#[derive(Serialize, Deserialize)]
struct MOTDPlayers {
    max: u32,
    online: u32,
    sample: Option<Vec<MOTDPlayer>>
}

#[derive(Serialize, Deserialize)]
struct MOTDPlayer {
    name: String,
    id: String
}

#[derive(Serialize, Deserialize)]
struct MOTDVersion {
    name: String,
    protocol: u32
}

#[derive(Serialize, Deserialize)]
struct MOTD {
    description: MOTDDescription,
    players: MOTDPlayers,
    version: MOTDVersion,
    favicon: Option<String>
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let file = include_str!("../out.json");
    let entries: Vec<IPEntry> = serde_json::from_str(file)?;

    let mut futures = vec![];

    entries.iter()
        .for_each(|entry|
            entry.ports.iter().for_each(|port|
                futures.push(async { perform_scan(&entry.ip, port.port).await.unwrap() })
            )
        );

    #[cfg(debug_assertions)]
    futures.truncate(1);

    tokio::fs::create_dir("data").await.unwrap_or_default(); // We dont care about the error

    futures::future::join_all(futures).await;

    Ok(())
}

async fn perform_scan(ip: &str, port: u16) -> anyhow::Result<()> {
    info!("Scanning {}:{}", ip, port);

    let mut stream = TcpStream::connect((ip, port)).await?;

    // lets build a handshake packet
    let mut handshake_data = BytesMut::new();
    handshake_data.put_vi(760); // protocol version
    handshake_data.put_str(ip); // ip
    handshake_data.put_u16(port); // port
    handshake_data.put_vi(1); // state

    let mut handshake = BytesMut::new();
    handshake.put_vi(handshake_data.len() as u32 + 1); // packet length
    handshake.put_vi(0x00); // packet id (0x00 = handshake)
    handshake.put(handshake_data); // packet data

    // Send the handsake packet
    stream.write(&handshake).await?;

    let mut request = BytesMut::new();
    request.put_vi(1); // packet length
    request.put_vi(0x00); // packet id (0x00 = handshake)

    // Send the request packet
    stream.write(&request).await?;

    // Read the response
    let mut response = BytesMut::with_capacity(0xFFFFF); // 1MB
    let mut buffer = [0u8; 0xFF]; // 255 bytes

    while let Ok(result) = timeout(Duration::from_millis(500), stream.read(&mut buffer)).await {
        match result {
            Ok(len) => {
                if len == 0 {
                    break;
                }
    
                response.put(&buffer[..len]);
            },
            Err(_) => { // timeout
                break;
            }
        }
    }

    let mut response = response.freeze();

    // lets strip away the packet length and string length, we dont need them
    let mut count = 0;

    while count < 3 {
        while !is_last(response[count]) {
            response.advance(1);
        }

        response.advance(1);
        count += 1;
    }

    stream.shutdown().await?; // shutdown so we dont have to wait for too long

    let response: MOTD = serde_json::from_slice(&response)?;

    // Filter out some servers we dont want
    if response.players.max != 50 || response.favicon.is_none() || response.version.protocol != 760 {
        return Ok(());
    }

    let mut file = tokio::fs::File::create(format!("data/{}.json", ip)).await?;
    file.write_all(serde_json::to_string_pretty(&response)?.as_bytes()).await?;

    // Extract the favicon
    if let Some(favicon) = response.favicon {
        let mut file = tokio::fs::File::create(format!("data/{}.png", ip)).await?;
        file.write_all(&base64::decode(&favicon[22..])?).await?;
    }
    
    Ok(())
}

trait BytesMutExt: BufMut {
    fn put_vi(&mut self, value: u32) where Self: Sized {
        let mut tmp_buffer = [0u8; 5];
        self.put(unsigned_varint::encode::u32(value, &mut tmp_buffer));
    }

    fn put_str(&mut self, value: &str) where Self: Sized {
        self.put_vi(value.len() as u32);
        self.put(value.as_bytes());
    }
}

impl BytesMutExt for BytesMut { }
