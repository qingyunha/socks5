use std::net::{IpAddr, Ipv4Addr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::runtime::Builder;

fn main() {
    // single thread
    let rt = Builder::new_current_thread().enable_io().build().unwrap();
    rt.block_on(server())
}

async fn server() {
    let listener = TcpListener::bind("0.0.0.0:1080").await.unwrap();
    loop {
        let (socket, _addr) = listener.accept().await.unwrap();
        tokio::spawn(async move {
            match handle(socket).await {
                Ok(_) => (),
                Err(e) => println!("handle error {}", e),
            }
        });
    }
}

async fn handle(mut stream: TcpStream) -> Result<(), Box<dyn std::error::Error>> {
    let mut tmp = [0u8; 5];
    stream.read_exact(&mut tmp[..1]).await?;
    if tmp[0] != 0x05 {
        return Err(format!("version not match {}", tmp[0]).into());
    }

    stream.read_exact(&mut tmp[..1]).await?;
    let nmethods = tmp[0] as usize;
    if nmethods > 5 {
        return Err(format!("too many conn methods error").into());
    }

    stream.read_exact(&mut tmp[..nmethods]).await?;

    let mut noauth = false;
    for m in &tmp[..nmethods] {
        if *m == 0 {
            noauth = true
        }
    }

    if !noauth {
        stream.write_all(b"\x05\xff").await?;
        return Err(format!("only support no auth").into());
    }
    stream.write_all(b"\x05\x00").await?;

    // read request
    stream.read_exact(&mut tmp[..1]).await?;
    if tmp[0] != 0x05 {
        return Err(format!("version not match {}", tmp[0]).into());
    }

    stream.read_exact(&mut tmp[..1]).await?;
    match tmp[0] {
        0x01 | 0x02 | 0x03 => (),
        _ => return Err(format!("unknown command {}", tmp[0]).into()),
    }
    if tmp[0] != 0x01 {
        return Err(format!("only support connect command").into());
    }

    // ignore RSV
    stream.read_exact(&mut tmp[..1]).await?;

    stream.read_exact(&mut tmp[..1]).await?;
    let atype = tmp[0];
    let conn;
    match atype {
        0x01 => {
            stream.read_exact(&mut tmp[..4]).await?;
            let ip = Ipv4Addr::new(tmp[0], tmp[1], tmp[2], tmp[3]);
            stream.read_exact(&mut tmp[..2]).await?;
            let port = ((tmp[0] as u16) << 8) + tmp[1] as u16;
            conn = TcpStream::connect((ip, port)).await?;
        }
        0x03 => {
            stream.read_exact(&mut tmp[..1]).await?;
            let length = tmp[0];
            let mut domain = vec![0; length as usize];
            stream.read_exact(&mut domain).await?;
            stream.read_exact(&mut tmp[..2]).await?;
            let port = ((tmp[0] as u16) << 8) + tmp[1] as u16;
            conn = TcpStream::connect((std::str::from_utf8(&domain)?, port)).await?;
        }
        0x04 => return Err(format!("no support ipv6").into()),
        _ => return Err(format!("unknown atype").into()),
    };

    let local_addr = conn.local_addr()?;
    let local_ip = if let IpAddr::V4(ip) = local_addr.ip() {
        ip
    } else {
        return Err(format!("should no be ipv6 addr").into());
    };
    let local_port = local_addr.port();

    stream.write_all(b"\x05\x00\x00\x01").await?;
    stream.write_all(&local_ip.octets()).await?;
    stream.write_all(&local_port.to_be_bytes()).await?;
    stream.flush().await?;

    let (mut reader, mut writer) = stream.into_split();
    let (mut reader1, mut writer1) = conn.into_split();
    let t1 = tokio::spawn(async move {
        match tokio::io::copy(&mut reader, &mut writer1).await {
            Ok(_) => (),
            Err(e) => println!("io copy error {}", e),
        }
    });
    let t2 = tokio::spawn(async move {
        match tokio::io::copy(&mut reader1, &mut writer).await {
            Ok(_) => (),
            Err(e) => println!("io copy error {}", e),
        }
    });

    t1.await?;
    t2.await?;

    Ok(())
}
