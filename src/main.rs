extern crate tokio;
extern crate log;
extern crate url;
extern crate serde;

use serde::{Serialize, Deserialize};
use futures_util::{future, pin_mut,StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_tungstenite::{connect_async, tungstenite::protocol::Message};
use std::time::{SystemTime, UNIX_EPOCH};
use log::info;
use url::Url;
use sha2::Sha256;
use hmac::{Hmac, Mac, NewMac};
use hex;

#[derive(Debug)]
struct ApiKeys {
    api_key: String,
    user_id: String,
    secret: String
}

#[derive(Debug)]
struct Signature {
    timestamp: u64,
    hmac_signature: String
}

#[derive(Serialize, Deserialize, Debug)]
struct Auth_OBJ {
    key: String,
    signature: String,
    timestamp: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct API_Auth {
    e: String,
    auth: Auth_OBJ,
    oid: String
}

fn create_signature(key: String, secret: String) -> Signature{
    let mut _timestamp = 0;
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(n) => _timestamp = n.as_secs(),
        Err(_) => print!("Error")
    }
    let mut first_part_key = _timestamp.to_string().to_owned();
    let borrowed_key = &key;
    first_part_key.push_str(borrowed_key);
    type HmacSha256 = Hmac<Sha256>;

    let mut mac = HmacSha256::new_varkey(first_part_key.as_bytes())
        .expect("Something");
    let mut _ts =  _timestamp.to_string();
    mac.update(_ts.as_bytes());
    let result = mac.finalize();
    return  Signature{
        timestamp: _timestamp,
        hmac_signature: hex::encode(result.into_bytes().as_slice().to_vec())
    }

}

fn get_signature(api_keys: ApiKeys) -> String{
    let sing = create_signature(api_keys.api_key, api_keys.secret);
    let api_keys = Auth_OBJ{
        key: api_keys.api_key,
        signature: sing.hmac_signature.to_uppercase(),
        timestamp: String::from(sing.timestamp)
    };
    api_auth = API_AUTH{
        e: String::from("auth"),
        auth: api_keys,
        oid: String::from("auth")
    }
    return serde_json::to_str(&api_auth).unwrap();
}

#[tokio::main]
async fn main() {
    let connect_addres = "wss://ws.cex.io/ws/";
    let url = Url::parse(&connect_addres).unwrap();
    let _api_keys = ApiKeys{api_key: String::from("mSwkNCjB9xaIrWQuWDnsbghKRc"),
                            user_id: String::from("up134935852"),
                            secret: String::from("fgII1PmKZdx5m23hFJnv70Wjp5w")};
    let (ws_stream, _) = connect_async(url)
        .await.expect("Failed to connect");
    info!("Finished websocket handshake");
    print!("Finished handshake");
    let (mut write, read) = ws_stream.split();

    let sign =  get_signature(_api_keys);
    println!("{}", sign)

    let ws_to_stout = {
        read.for_each(| message| async {
            let data = message.unwrap().into_data();
            print!("{:?}", data);
            tokio::io::stdout().write_all(&data).await.unwrap();
        })
    };
    ws_to_stout.await;

}
